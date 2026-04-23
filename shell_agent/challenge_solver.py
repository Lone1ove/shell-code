"""
单题解题逻辑模块
================

负责单个题目的解题流程：
- 自动侦察
- Agent 执行
- 结果处理
- 动态槽位填充
"""
import uuid
import time
import asyncio
import os
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from langfuse.langchain import CallbackHandler
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import HumanMessage

from shell_agent.state import PenetrationTesterState
from shell_agent.common import (
    calibrated_finding_probability,
    count_actionable_findings,
    has_actionable_confirmed_findings,
    has_strong_verification_signal,
    is_high_value_active_finding,
    log_system_event,
)
from shell_agent.retry_strategy import RetryStrategy
from shell_agent.utils.util import is_authentication_error
from shell_agent.reporting import save_report_files
from shell_agent.finding_identity import finding_identity_key
from shell_agent.working_memory import (
    persist_working_memory,
    load_decision_memory_context,
    load_structured_working_memory,
    recover_findings_from_working_memory,
    reset_transient_working_memory,
)


def _describe_model(model_obj) -> Dict:
    return {
        "class": type(model_obj).__name__,
        "model": getattr(model_obj, "model_name", None) or getattr(model_obj, "model", None) or "unknown",
        "base_url": getattr(model_obj, "openai_api_base", None) or getattr(model_obj, "base_url", None) or "unknown",
    }


def _to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _benchmark_priors_enabled() -> bool:
    return os.getenv("ENABLE_BENCHMARK_PRIORS", "false").strip().lower() == "true"


def _merge_unique_hints(existing: List[str], incoming: List[str], *, limit: int = 12) -> List[str]:
    merged: List[str] = []
    seen = set()
    for item in list(existing or []) + list(incoming or []):
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(text)
    return merged[-limit:]


def _normalize_recon_surface_hint(candidate: str) -> str:
    text = str(candidate or "").strip().strip("`'\"")
    if not text:
        return ""
    text = text.rstrip(".,;:!?)>")
    parsed = urlparse(text if text.startswith(("http://", "https://", "/")) else f"/{text}")
    path = str(parsed.path or "").strip().lower()
    if not path.startswith("/"):
        return ""
    # Ignore trivial root-like hints.
    if path in {"/", "/index", "/home"}:
        return ""
    query_keys = sorted(
        {
            str(part).split("=", 1)[0].strip().lower()
            for part in str(parsed.query or "").split("&")
            if str(part).strip()
        }
    )
    query = f"?{'&'.join(query_keys)}" if query_keys else ""
    normalized = f"{path}{query}"
    useful_markers = [".action", ".jsp", ".php", ".do", "/api/", "/upload", "/debug", "/console", "?"]
    if any(marker in normalized for marker in useful_markers) or normalized.count("/") >= 2:
        return normalized
    return ""


def _extract_surface_hints_from_recon_result(recon_result: Dict) -> List[str]:
    hints: List[str] = []
    if not isinstance(recon_result, dict):
        return hints

    for form in list(recon_result.get("forms") or []):
        action = str((form or {}).get("action") or "").strip()
        normalized = _normalize_recon_surface_hint(action)
        if normalized:
            hints.append(normalized)

    html = str(recon_result.get("html_content") or "")
    if html:
        for action in re.findall(r'action=["\']([/\w.\-;?=&%]+)["\']', html, flags=re.IGNORECASE):
            normalized = _normalize_recon_surface_hint(action)
            if normalized:
                hints.append(normalized)

    return _merge_unique_hints([], hints, limit=12)


def _build_initial_state(challenge: Dict, challenge_code: str) -> PenetrationTesterState:
    return {
        "challenges": [challenge],
        "current_challenge": challenge,
        "total_challenges": 1,
        "solved_count": 0,
        "unsolved_count": 1,
        "current_score": 0,
        "start_time": time.time(),
        "flag": None,
        "is_finished": False,
        "findings": [],
        "vulnerability_detected": False,
        "detection_metrics": {},
        "action_history": [],
        "last_node": "advisor",
        "execution_attempts": 0,
        "advisor_suggestion": None,
        "last_execution_outcome": None,
        "consecutive_failures": 0,
        "connectivity_failures": 0,
        "total_connectivity_failures": 0,
        "no_action_rounds": 0,
        "no_progress_rounds": 0,
        "advisor_loop_rounds": 0,
        "request_advisor_help": False,
        "last_task_signature": None,
        "repeated_task_rounds": 0,
        "last_hypothesis_signature": None,
        "repeated_hypothesis_rounds": 0,
        "candidate_surface_hints": [],
        "blocked_hypothesis_signatures": [],
        "pending_task": None,
        "pending_flag": None,
        "advisor_rounds": 0,
        "main_rounds": 0,
        "poc_rounds": 0,
        "docker_rounds": 0,
        "tool_rounds": 0,
    }


def _finding_probability(finding: Dict) -> float:
    return calibrated_finding_probability(finding)


def _finding_key(finding: Dict) -> str:
    return finding_identity_key(finding)


def _extract_agent_metrics(state: Dict) -> Dict[str, int]:
    return {
        "advisor_rounds": int(state.get("advisor_rounds", 0) or 0),
        "main_rounds": int(state.get("main_rounds", 0) or 0),
        "poc_rounds": int(state.get("poc_rounds", 0) or 0),
        "docker_rounds": int(state.get("docker_rounds", 0) or 0),
        "tool_rounds": int(state.get("tool_rounds", 0) or 0),
    }


def _extract_execution_attempts(state: Dict) -> int:
    explicit = int(state.get("execution_attempts", 0) or 0)
    if explicit > 0:
        return explicit
    return max(
        int(state.get("tool_rounds", 0) or 0),
        int(state.get("poc_rounds", 0) or 0) + int(state.get("docker_rounds", 0) or 0),
    )


def _recover_partial_timeout_result(
    challenge: Dict,
    challenge_code: str,
    elapsed_time: float,
    objective_mode: str,
) -> Dict:
    memory = load_structured_working_memory(challenge_code)
    findings = recover_findings_from_working_memory(challenge_code)
    detection_metrics = _build_detection_metrics_from_findings(findings, elapsed_time)
    counters = dict(memory.get("counters") or {})
    detection_metrics["confirmed_count"] = max(
        int(detection_metrics.get("confirmed_count", 0) or 0),
        int(counters.get("confirmed_count", 0) or 0),
    )
    detection_metrics["suspected_count"] = max(
        int(detection_metrics.get("suspected_count", 0) or 0),
        int(counters.get("suspected_count", 0) or 0),
    )
    strict_confirmed_count = len(
        [
            f
            for f in findings
            if (f.get("status") or "").strip().lower() == "confirmed" and bool(f.get("strict_verified"))
        ]
    )
    vulnerability_detected = bool(
        int(detection_metrics.get("confirmed_count", 0) or 0) > 0
        or strict_confirmed_count > 0
        or has_actionable_confirmed_findings(findings)
    )
    if objective_mode == "flag":
        success = False
    else:
        success = vulnerability_detected

    report_md = None
    report_docx = None
    if findings or vulnerability_detected:
        try:
            report_md = save_report_files(
                challenge=challenge,
                result={
                    "success": success,
                    "objective_mode": objective_mode,
                    "vulnerability_detected": vulnerability_detected,
                    "findings": findings,
                    "detection_metrics": detection_metrics,
                    "flag": None,
                    "attempts": int(memory.get("execution_attempts", 0) or 0),
                    "elapsed_time": elapsed_time,
                    "agent_metrics": {
                        "advisor_rounds": 0,
                        "main_rounds": 0,
                        "poc_rounds": 0,
                        "docker_rounds": 0,
                        "tool_rounds": 0,
                    },
                    "error": "timeout_partial_recovery",
                },
            )
            report_docx = str(Path(report_md).with_suffix(".docx")) if report_md else None
        except Exception as report_error:
            log_system_event(
                "[报告] ⚠️ 超时后部分结果报告生成失败",
                {"error": str(report_error), "challenge_code": challenge_code},
                level=logging.WARNING,
            )

    return {
        "findings": findings,
        "detection_metrics": detection_metrics,
        "vulnerability_detected": vulnerability_detected,
        "success": success,
        "report_markdown": report_md,
        "report_docx": report_docx,
        "execution_attempts": int(memory.get("execution_attempts", 0) or 0),
    }


def _merge_agent_metrics(primary: Dict[str, int], second: Dict[str, int]) -> Dict[str, int]:
    return {
        "advisor_rounds": int(primary.get("advisor_rounds", 0)) + int(second.get("advisor_rounds", 0)),
        "main_rounds": int(primary.get("main_rounds", 0)) + int(second.get("main_rounds", 0)),
        "poc_rounds": int(primary.get("poc_rounds", 0)) + int(second.get("poc_rounds", 0)),
        "docker_rounds": int(primary.get("docker_rounds", 0)) + int(second.get("docker_rounds", 0)),
        "tool_rounds": int(primary.get("tool_rounds", 0)) + int(second.get("tool_rounds", 0)),
    }


def _has_strict_confirmed(findings: List[Dict]) -> bool:
    for f in findings or []:
        if (f.get("status") or "").strip().lower() == "confirmed" and bool(f.get("strict_verified")):
            return True
    return False


def _need_adaptive_recheck(findings: List[Dict], detection_metrics: Dict) -> Tuple[bool, str]:
    enabled = os.getenv("ADAPTIVE_RECHECK_ENABLED", "true").strip().lower() == "true"
    if not enabled:
        return False, "disabled"
    if not findings:
        return False, "no_findings"
    if _has_strict_confirmed(findings):
        return False, "already_strict_confirmed"

    active = [
        f
        for f in findings
        if has_actionable_confirmed_findings([f]) or is_high_value_active_finding(f)
    ]
    if not active:
        return False, "no_active_findings"

    top_prob = max(_finding_probability(f) for f in active)
    low = _to_float(os.getenv("ADAPTIVE_RECHECK_SCORE_LOW", "0.45"), 0.45)
    high = _to_float(os.getenv("ADAPTIVE_RECHECK_SCORE_HIGH", "0.85"), 0.85)
    in_uncertain_zone = low <= top_prob <= high

    uncertain_cve = any(
        f.get("cve") and (f.get("cve_verdict") or "").strip().lower() in {"weak_match", "unverified", "invalid_format"}
        for f in active
    )
    cve_set = {str(f.get("cve")).strip().upper() for f in active if f.get("cve")}
    cve_conflict = len(cve_set) > 1
    fpr = _to_float((detection_metrics or {}).get("false_positive_rate"), 0.0)
    fp_trigger = _to_float(os.getenv("ADAPTIVE_RECHECK_FP_TRIGGER", "0.2"), 0.2)
    high_fp = fpr >= fp_trigger

    should = in_uncertain_zone or uncertain_cve or cve_conflict or high_fp
    if not should:
        return False, "stable_enough"
    reason_parts = []
    if in_uncertain_zone:
        reason_parts.append(f"uncertain_zone:{top_prob:.3f}")
    if uncertain_cve:
        reason_parts.append("uncertain_cve")
    if cve_conflict:
        reason_parts.append("cve_conflict")
    if high_fp:
        reason_parts.append(f"high_fp:{fpr:.3f}")
    return True, ",".join(reason_parts)


def _build_recheck_context(challenge: Dict, findings: List[Dict]) -> str:
    target = challenge.get("_target_url") or ""
    priors_enabled = _benchmark_priors_enabled()
    expected_cves = [x.upper() for x in (challenge.get("_expected_cves") or []) if x] if priors_enabled else []
    expected_family = (challenge.get("_expected_family") or "").strip() if priors_enabled else ""
    lines = [
        "【自适应二次复检任务】",
        "目标：对首轮结果进行严格复检，优先排除误报并稳定结论。",
        f"目标地址：{target}",
        "",
        "规则：",
        "1. 本轮仅做最小化、确定性的验证动作；禁止大范围扫描。",
        "2. 若无运行时证据（uid/whoami/确定性回显），不得确认漏洞。",
        "3. 对相近CVE必须给出向量差异证据。",
        "4. 输出必须包含 PASS/FAIL 和依据。",
        "",
        "首轮待复检发现：",
    ]
    if priors_enabled:
        lines.insert(3, f"期望CVE：{', '.join(expected_cves) if expected_cves else 'N/A'}")
        lines.insert(4, f"期望家族：{expected_family or 'N/A'}")
    for idx, f in enumerate(findings or [], 1):
        lines.append(
            f"{idx}. {f.get('vuln_name')} | status={f.get('status')} | "
            f"existence={_finding_probability(f):.3f} | cve={f.get('cve') or 'N/A'} | "
            f"cve_verdict={f.get('cve_verdict') or 'absent'}"
        )
    return "\n".join(lines)


def _is_high_value_active_finding(finding: Dict) -> bool:
    return is_high_value_active_finding(finding)


def _is_persisted_confirmed_finding(finding: Dict) -> bool:
    if not isinstance(finding, dict):
        return False
    status = (finding.get("status") or "").strip().lower()
    if status != "confirmed":
        return False
    return has_strong_verification_signal(finding)


def _intersect_findings(primary: List[Dict], second: List[Dict]) -> Tuple[List[Dict], Dict]:
    second_map = {_finding_key(f): f for f in (second or []) if isinstance(f, dict)}
    primary_keys = {_finding_key(f) for f in (primary or []) if isinstance(f, dict)}
    merged: List[Dict] = []
    retained = 0
    downgraded = 0
    preserved_confirmed = 0
    supplemental = 0

    for item in primary or []:
        f1 = dict(item or {})
        k = _finding_key(f1)
        f2 = second_map.get(k)
        s1 = (f1.get("status") or "").strip().lower()
        if not f2:
            if _is_persisted_confirmed_finding(f1):
                notes = list(f1.get("uncertainty_notes", []) or [])
                notes.append(
                    "Adaptive recheck: retained previously confirmed finding because first-pass deterministic confirmation should not be forgotten."
                )
                f1["uncertainty_notes"] = notes
                preserved_confirmed += 1
                retained += 1
                merged.append(f1)
                continue
            if s1 != "rejected":
                if _is_high_value_active_finding(f1):
                    f1["status"] = "suspected"
                    f1["strict_verified"] = False
                    notes = list(f1.get("uncertainty_notes", []) or [])
                    notes.append(
                        "Adaptive recheck: second pass did not reproduce this high-value finding; retained as suspected instead of rejected."
                    )
                    f1["uncertainty_notes"] = notes
                    downgraded += 1
                    merged.append(f1)
                    continue
                f1["status"] = "rejected"
                f1["strict_verified"] = False
                notes = list(f1.get("uncertainty_notes", []) or [])
                notes.append("Adaptive recheck: not reproduced in second pass, downgraded to rejected.")
                f1["uncertainty_notes"] = notes
                downgraded += 1
            merged.append(f1)
            continue

        s2 = (f2.get("status") or "").strip().lower()
        if s1 in {"rejected"} or s2 in {"rejected"}:
            if _is_persisted_confirmed_finding(f1):
                notes = list(f1.get("uncertainty_notes", []) or [])
                notes.append(
                    "Adaptive recheck: preserved first-pass confirmed finding despite a later conflicting pass; manual contradiction review recommended."
                )
                f1["uncertainty_notes"] = notes
                preserved_confirmed += 1
                retained += 1
                merged.append(f1)
                continue
            if _is_high_value_active_finding(f1):
                f1["status"] = "suspected"
                f1["strict_verified"] = False
                notes = list(f1.get("uncertainty_notes", []) or [])
                notes.append(
                    "Adaptive recheck: second pass rejected a high-value first-pass finding; retained as suspected for manual review."
                )
                f1["uncertainty_notes"] = notes
                downgraded += 1
                merged.append(f1)
                continue
            f1["status"] = "rejected"
            f1["strict_verified"] = False
            notes = list(f1.get("uncertainty_notes", []) or [])
            notes.append("Adaptive recheck: at least one pass rejected this finding.")
            f1["uncertainty_notes"] = notes
            downgraded += 1
            merged.append(f1)
            continue

        retained += 1
        both_confirmed_strict = (
            s1 == "confirmed"
            and s2 == "confirmed"
            and bool(f1.get("strict_verified"))
            and bool(f2.get("strict_verified"))
        )
        if both_confirmed_strict:
            f1["status"] = "confirmed"
            f1["strict_verified"] = True
        else:
            f1["status"] = "suspected"
            f1["strict_verified"] = False
        score1 = _to_float(f1.get("score"), _finding_probability(f1))
        score2 = _to_float(f2.get("score"), _finding_probability(f2))
        f1["score"] = round(min(score1, score2), 4)
        conf1 = _to_float(f1.get("confidence"), _finding_probability(f1))
        conf2 = _to_float(f2.get("confidence"), _finding_probability(f2))
        f1["confidence"] = round(min(conf1, conf2), 4)
        notes = list(f1.get("uncertainty_notes", []) or [])
        notes.append("Adaptive recheck: retained by intersection of first and second pass.")
        if not both_confirmed_strict:
            notes.append("Intersection passed but strict confirmed criteria not met in both passes.")
        # 去重保持顺序
        dedup_notes = []
        seen_notes = set()
        for n in notes:
            key = str(n).strip().lower()
            if not key or key in seen_notes:
                continue
            seen_notes.add(key)
            dedup_notes.append(n)
        f1["uncertainty_notes"] = dedup_notes
        merged.append(f1)

    for item in second or []:
        if not isinstance(item, dict):
            continue
        key = _finding_key(item)
        if key in primary_keys:
            continue
        status = (item.get("status") or "").strip().lower()
        if status not in {"confirmed", "suspected"} and not _is_high_value_active_finding(item):
            continue
        extra = dict(item)
        notes = list(extra.get("uncertainty_notes", []) or [])
        notes.append("Adaptive recheck: additional finding observed only in the second pass.")
        extra["uncertainty_notes"] = notes
        supplemental += 1
        merged.append(extra)

    meta = {
        "primary_count": len(primary or []),
        "second_count": len(second or []),
        "retained_by_intersection": retained,
        "downgraded_count": downgraded,
        "preserved_confirmed_count": preserved_confirmed,
        "second_pass_only_count": supplemental,
    }
    return merged, meta


def _merge_with_working_memory_findings(challenge_code: str, findings: List[Dict]) -> List[Dict]:
    recovered = recover_findings_from_working_memory(challenge_code)
    merged: Dict[str, Dict] = {}

    def _rank(item: Dict) -> tuple:
        checks = dict(item.get("verification_checks") or {})
        status = (item.get("status") or "").strip().lower()
        return (
            1 if status == "confirmed" and bool(item.get("strict_verified")) else 0,
            1 if bool(checks.get("explicit_success_signal")) else 0,
            1 if bool(checks.get("runtime_signal")) else 0,
            float(item.get("score") or item.get("confidence") or 0.0),
        )

    for item in list(findings or []) + list(recovered or []):
        if not isinstance(item, dict):
            continue
        key = finding_identity_key(item)
        current = merged.get(key)
        if current is None or _rank(item) > _rank(current):
            merged[key] = dict(item)

    values = list(merged.values())
    values.sort(key=_rank, reverse=True)
    return values


def _build_detection_metrics_from_findings(findings: List[Dict], elapsed_time: float) -> Dict:
    total = len(findings or [])
    actionable_counts = count_actionable_findings(findings)
    rejected = [f for f in (findings or []) if (f.get("status") or "").lower() == "rejected"]

    family_distribution: Dict[str, int] = {}
    uncertain_cve_count = 0
    strict_verified_count = 0
    for f in findings or []:
        if f.get("cve") and (f.get("cve_verdict") or "").lower() in {"invalid_format", "unverified", "weak_match"}:
            uncertain_cve_count += 1
        if bool(f.get("strict_verified")):
            strict_verified_count += 1
    for f in (findings or []):
        if not has_actionable_confirmed_findings([f]):
            continue
        fam = f.get("template_id") or f.get("vuln_type", "unknown")
        family_distribution[fam] = family_distribution.get(fam, 0) + 1

    false_positive_rate = (len(rejected) / total) if total else 0.0
    return {
        "total_findings": total,
        "confirmed_count": actionable_counts.get("confirmed", 0),
        "suspected_count": actionable_counts.get("suspected", 0),
        "rejected_count": len(rejected),
        "false_positive_rate": round(false_positive_rate, 4),
        "avg_detection_time_seconds": round(float(elapsed_time or 0.0), 2),
        "cve_family_distribution": family_distribution,
        "uncertain_cve_count": uncertain_cve_count,
        "strict_verified_count": strict_verified_count,
    }


async def solve_single_challenge(
    challenge: Dict,
    main_llm,
    advisor_llm,
    config,
    langfuse_handler: Optional[CallbackHandler],  # 可选
    task_manager,  # ⭐ 新增：任务管理器
    concurrent_semaphore,  # ⭐ 新增：并发信号量
    retry_strategy: Optional[RetryStrategy] = None,  # ⭐ 新增：重试策略
    attempt_history: Optional[list] = None,  # ⭐ 新增：历史尝试记录
    strategy_description: str = "Fixed Roles (main + advisor)",  # ⭐ 新增：策略描述
    langfuse_metadata: Optional[Dict] = None  # ⭐ 新增：Langfuse 元数据
) -> Dict:
    """
    解决单个题目（完全异常隔离，单题失败不影响其他题）

    Args:
        challenge: 题目信息
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        config: 配置
        langfuse_handler: Langfuse 回调
        task_manager: 任务管理器
        retry_strategy: 重试策略（可选）
        attempt_history: 历史尝试记录（可选）
        strategy_description: 策略描述

    Returns:
        解题结果 {code, flag, score, attempts, success}

    CRITICAL: 此函数保证任何异常都不会向外传播，始终返回结果字典
    """
    challenge_code = challenge.get("challenge_code", "unknown")
    difficulty = challenge.get("difficulty", "unknown")
    points = challenge.get("points", 0)

    # ⭐ 设置题目日志上下文（创建独立日志文件）
    from shell_agent.common import set_challenge_context, clear_challenge_context
    set_challenge_context(challenge_code)

    # ⭐ 设置当前题目的记忆隔离
    try:
        from shell_agent.tools.memory_tools import set_current_challenge
        set_current_challenge(challenge_code)
    except Exception as e:
        log_system_event(
            f"[记忆] ⚠️ 设置题目记忆隔离失败: {str(e)}",
            level=logging.WARNING
        )

    # 获取当前任务管理器状态
    status = await task_manager.get_status()

    log_system_event(
        f"[解题] 开始攻击: {challenge_code}",
        {
            "difficulty": difficulty,
            "points": points,
            "strategy": strategy_description,
            "main_model_runtime": _describe_model(main_llm),
            "advisor_model_runtime": _describe_model(advisor_llm),
            "active_tasks": status['active_count'],
            "completed": status['completed_count']
        }
    )

    # ⭐ 使用 try-finally 确保上下文一定会被清除
    try:
        # 为每个题目创建独立的状态
        initial_state: PenetrationTesterState = _build_initial_state(challenge, challenge_code)
        reset_transient_working_memory(challenge_code)
        log_system_event(
            "[工作记忆] 已重置跨轮规划瞬态状态",
            {"challenge_code": challenge_code},
        )
        persist_working_memory(initial_state)

        # ==================== 自动信息收集（在 Agent 启动前） ====================
        target_info = challenge.get("target_info", {})
        target_ip = target_info.get("ip")
        target_ports = target_info.get("port", [])

        messages_to_inject = []

        # ⭐ 0. 自动获取提示（在所有信息收集之前）
        # ⭐ 手动模式跳过 API 调用
        is_manual_mode = challenge.get("_manual_mode", True)

        if is_manual_mode:
            log_system_event(
                f"[手动模式] 跳过自动获取提示（无 API）",
                {"challenge_code": challenge_code}
            )
            manual_hint = os.getenv("MANUAL_HINT_CONTENT", "").strip()
            if manual_hint:
                challenge["hint_content"] = manual_hint
                messages_to_inject.append(
                    HumanMessage(content=f"💡 **手动提示**\n\n{manual_hint}")
                )
                log_system_event(
                    "[手动模式] 已注入手动提示",
                    {"hint_preview": manual_hint[:120]}
                )
        else:
            try:
                from shell_agent.tools.competition_api_tools import CompetitionAPIClient
                hint_client = CompetitionAPIClient()
                hint_data = hint_client.get_hint(challenge_code)

                hint_content = hint_data.get("hint_content", "")
                if hint_content:
                    messages_to_inject.append(
                        HumanMessage(content=f"💡 **官方提示**\n\n{hint_content}")
                    )
                    challenge["hint_content"] = hint_content
                    log_system_event(
                        f"[自动提示] ✅ 已获取提示: {challenge_code}",
                        {"hint_preview": hint_content[:100]}
                    )
            except Exception as hint_error:
                log_system_event(
                    f"[自动提示] ⚠️ 获取提示失败: {str(hint_error)}",
                    level=logging.WARNING
                )

        # ⭐ 消息注入顺序设计说明：
        #
        # 注入顺序：[自动侦察结果] → [历史尝试记录]
        #
        # 设计理由：
        # 1. **自动侦察优先**：让 Agent 首先看到最新的目标信息（HTML、响应头等）
        #    - 这是每次重试都会执行的新鲜数据
        #    - 帮助 Agent 快速了解目标状态
        #
        # 2. **历史记录在后**：在新信息之后提供历史失败经验
        #    - 避免 Agent 被历史失败方法先入为主
        #    - 鼓励 Agent 基于新侦察结果思考新方法
        #    - 历史记录作为"避坑指南"而非主导思路
        #
        # 3. **失败处理**：即使侦察失败，也会注入失败信息
        #    - 让 Agent 知道自动侦察尝试过但失败了
        #    - 提示 Agent 需要手动收集信息
        #
        # 注意：LangGraph 的消息顺序会影响 LLM 的注意力分配，
        #       最新的消息通常会获得更多关注。

        # ⭐ 1. 自动侦察（优先注入）
        if target_ip and target_ports:
            # ⭐ 修复：对所有端口进行侦察（支持多端口场景）
            ports_to_scan = target_ports if isinstance(target_ports, list) else [target_ports]
            
            log_system_event(
                f"[自动侦察] 开始收集目标信息: {target_ip}, challenge_code: {challenge_code}, ports: {ports_to_scan}",
                {}
            )

            try:
                from shell_agent.utils.recon import auto_recon_web_target, format_recon_result_for_llm

                # ⭐ 对每个端口进行侦察
                all_recon_summaries = []
                successful_ports = []
                failed_ports = []
                recon_surface_hints: List[str] = []

                for target_port in ports_to_scan:
                    try:
                        # 执行自动侦察（提高超时时间到 30 秒）
                        recon_result = auto_recon_web_target(target_ip, target_port, timeout=30)
                        recon_surface_hints = _merge_unique_hints(
                            recon_surface_hints,
                            _extract_surface_hints_from_recon_result(recon_result),
                            limit=12,
                        )

                        # 将侦察结果格式化
                        recon_summary = format_recon_result_for_llm(recon_result)
                        all_recon_summaries.append(
                            f"### 端口 {target_port}\n{recon_summary}"
                        )

                        successful_ports.append(target_port)
                        
                        log_system_event(
                            f"[自动侦察] ✅ 端口 {target_port} 信息收集完成",
                            {
                                "success": recon_result["success"],
                                "status_code": recon_result.get("status_code"),
                                "content_length": recon_result.get("html_length", 0)
                            }
                        )

                    except Exception as port_error:
                        failed_ports.append(target_port)
                        log_system_event(
                            f"[自动侦察] ⚠️ 端口 {target_port} 侦察失败: {str(port_error)}",
                            level=logging.WARNING
                        )
                        all_recon_summaries.append(
                            f"### 端口 {target_port}\n⚠️ 侦察失败: {str(port_error)}"
                        )

                # ⭐ 汇总所有端口的侦察结果
                if all_recon_summaries:
                    combined_summary = "\n\n".join(all_recon_summaries)
                    messages_to_inject.append(
                        HumanMessage(content=f"🔍 系统自动侦察结果：\n\n{combined_summary}")
                    )
                    if recon_surface_hints:
                        initial_state["candidate_surface_hints"] = _merge_unique_hints(
                            list(initial_state.get("candidate_surface_hints") or []),
                            recon_surface_hints,
                            limit=12,
                        )

                    # 记录到 action_history
                    initial_state["action_history"].append(
                        f"[自动侦察] 已扫描 {len(ports_to_scan)} 个端口：成功 {len(successful_ports)} 个，失败 {len(failed_ports)} 个"
                    )
                    if recon_surface_hints:
                        initial_state["action_history"].append(
                            "[CandidateSurfaces/Reconn] " + ", ".join(recon_surface_hints[:4])
                        )

                # ⭐ 如果全部端口都失败，额外提示
                if len(failed_ports) == len(ports_to_scan):
                    messages_to_inject.append(
                        HumanMessage(
                            content=f"⚠️ 所有端口自动侦察均失败\n\n"
                            f"建议: 请使用 execute_python_poc 或 execute_command 手动收集目标信息"
                        )
                    )

            except Exception as recon_error:
                log_system_event(
                    f"[自动侦察] ⚠️ 侦察模块异常: {str(recon_error)}",
                    level=logging.WARNING
                )
                # ⭐ 改进：侦察失败时也注入失败信息，让 Agent 知道需要手动收集
                messages_to_inject.append(
                    HumanMessage(
                        content=f"⚠️ 系统自动侦察失败\n\n"
                        f"错误信息: {str(recon_error)}\n\n"
                        f"建议: 请使用 execute_python_poc 或 execute_command 手动收集目标信息"
                    )
                )
                initial_state["action_history"].append(
                    f"[自动侦察] 侦察失败: {str(recon_error)}"
                )
        else:
            log_system_event(
                f"[自动侦察] ⚠️ 无法获取目标信息，跳过自动侦察",
                {"challenge": challenge},
                level=logging.WARNING
            )

        # ⭐ 2. 注入历史尝试记录（后注入，让 Agent 在新侦察结果后看到历史）
        if attempt_history and retry_strategy:
            history_summary = retry_strategy.format_attempt_history(attempt_history)
            if history_summary:
                messages_to_inject.append(
                    HumanMessage(content=f"📜 **历史尝试记录**\n\n{history_summary}")
                )
                log_system_event(
                    f"[解题] 注入历史记录",
                    {"attempts_count": len(attempt_history)}
                )

        prior_working_memory = load_decision_memory_context(
            challenge_code,
            max_chars=int(os.getenv("WORKING_MEMORY_RETRY_INJECT_MAX_CHARS", "3600")),
        )
        if prior_working_memory:
            messages_to_inject.append(
                HumanMessage(content=f"🧠 **中间过程决策记忆**\n\n{prior_working_memory}")
            )
            log_system_event(
                "[解题] 注入中间过程决策记忆",
                {"challenge_code": challenge_code},
            )

        # ⭐ 3. 将所有消息注入到初始状态
        if messages_to_inject:
            initial_state["messages"] = messages_to_inject

        # ==================== 自动信息收集结束 ====================

        # 构建独立的 Agent 图
        # 注意: build_multi_agent_graph 现在只接受 config 参数 (LangGraph Studio 兼容)
        # 但我们需要传入自定义的 LLM,所以需要创建一个包装函数
        from shell_agent.graph import build_multi_agent_graph_with_llms

        # 使用 challenge_code 作为图名称（用于 Langfuse trace name）
        app = await build_multi_agent_graph_with_llms(
            main_llm=main_llm,
            advisor_llm=advisor_llm,
            manual_mode=is_manual_mode,
            graph_name=challenge_code
        )

        # 配置运行参数
        from shell_agent.core.constants import AgentConfig

        thread_id = str(uuid.uuid4())
        recursion_limit = AgentConfig.get_recursion_limit()

        # 构建 RunnableConfig，包含 Langfuse 元数据
        runnable_config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "configuration": config.__dict__,
            },
            "callbacks": [langfuse_handler] if langfuse_handler else [],
            "recursion_limit": recursion_limit,
            # Langfuse: 通过 run_name 设置 trace name
            "run_name": challenge_code,
            # Langfuse 3.x: 通过 metadata 传递 session_id/tags
            "metadata": langfuse_metadata or {}
        }

        # 最外层异常保护：确保此函数永远不会抛出异常
        try:
            start_time = time.time()

            # ⭐ 执行 Agent（使用并发限制器 + 超时保护）
            task_timeout = AgentConfig.get_single_task_timeout()
            objective_mode = os.getenv("OBJECTIVE_MODE", "hybrid").strip().lower()
            if objective_mode not in {"detect", "flag", "hybrid"}:
                objective_mode = "hybrid"
            try:
                # ⭐ 修复：移除对私有属性 concurrent_semaphore._value 的访问
                # 避免重复读取环境变量，使用更稳定的方式
                async with concurrent_semaphore:
                    log_system_event(
                        f"[并发控制] 获取执行槽位: {challenge_code}",
                        {"状态": "已获取信号量"}
                    )

                    async with asyncio.timeout(task_timeout):
                        # ⭐ 使用 with_config 设置 run_name（Langfuse trace name）
                        final_state = await app.with_config({"run_name": challenge_code}).ainvoke(initial_state, runnable_config)
            except asyncio.TimeoutError:
                log_system_event(
                    f"[解题] ⏱️ 超时: {challenge_code}（{task_timeout}秒）",
                    level=logging.WARNING
                )
                persist_working_memory(initial_state, error=f"task_timeout_{task_timeout}s")
                recovered = _recover_partial_timeout_result(
                    challenge=challenge,
                    challenge_code=challenge_code,
                    elapsed_time=task_timeout,
                    objective_mode=objective_mode,
                )

                # ⭐ 提取尝试摘要（即使超时也要记录）
                attempt_summary = retry_strategy.extract_attempt_summary(
                    initial_state, strategy_description
                ) if retry_strategy else None

                await task_manager.remove_task(
                    challenge_code,
                    success=bool(recovered.get("success")),
                    attempt_summary=attempt_summary,
                )
                return {
                    "code": challenge_code,
                    "flag": None,
                    "findings": recovered.get("findings", []),
                    "vulnerability_detected": recovered.get("vulnerability_detected", False),
                    "detection_metrics": recovered.get("detection_metrics", {}),
                    "report_markdown": recovered.get("report_markdown"),
                    "report_docx": recovered.get("report_docx"),
                    "score": points if recovered.get("success") else 0,
                    "attempts": int(recovered.get("execution_attempts", 0) or 0),
                    "success": bool(recovered.get("success")),
                    "timeout": True,
                    "objective_mode": objective_mode,
                    "elapsed_time": task_timeout
                }
            except KeyboardInterrupt:
                # 允许用户手动中断
                log_system_event(
                    f"[解题] 🛑 用户中断: {challenge_code}",
                    level=logging.WARNING
                )
                raise  # KeyboardInterrupt 应该向上传播
            except Exception as agent_error:
                # Agent 执行异常（网络、API、LLM 错误等）
                import traceback
                error_traceback = traceback.format_exc()
                log_system_event(
                    f"[解题] ⚠️ Agent 执行异常: {challenge_code}",
                    {
                        "error_type": type(agent_error).__name__,
                        "error_message": str(agent_error),
                        "error_args": getattr(agent_error, 'args', None),
                        "initial_state_keys": list(initial_state.keys()) if initial_state else None,
                        "has_messages": "messages" in initial_state if initial_state else None,
                        "traceback": error_traceback
                    },
                    level=logging.ERROR
                )
                # 同时打印完整堆栈到控制台
                print(f"\n{'='*60}")
                print(f"[DEBUG] Agent 执行异常详情:")
                print(f"{'='*60}")
                print(f"错误类型: {type(agent_error).__name__}")
                print(f"错误信息: {str(agent_error)}")
                print(f"错误参数: {getattr(agent_error, 'args', None)}")
                print(f"initial_state 字段: {list(initial_state.keys()) if initial_state else 'None'}")
                print(f"是否包含 messages: {'messages' in initial_state if initial_state else 'N/A'}")
                print(f"\n完整堆栈追踪:")
                print(error_traceback)
                print(f"{'='*60}\n")
                persist_working_memory(initial_state, error=f"agent_error: {str(agent_error)}")
                await task_manager.remove_task(challenge_code, success=False)
                return {
                    "code": challenge_code,
                    "flag": None,
                    "score": 0,
                    "attempts": 0,
                    "success": False,
                    "error": f"agent_error: {str(agent_error)}",
                    "elapsed_time": time.time() - start_time
                }

            elapsed_time = time.time() - start_time
            flag = final_state.get("flag")
            findings = final_state.get("findings", []) or []
            findings = _merge_with_working_memory_findings(challenge_code, findings)
            detection_metrics = _build_detection_metrics_from_findings(
                findings,
                time.time() - start_time,
            )
            detection_metrics.update(dict(final_state.get("detection_metrics", {}) or {}))
            attempts = _extract_execution_attempts(final_state)
            agent_metrics = _extract_agent_metrics(final_state)

            need_recheck, recheck_reason = _need_adaptive_recheck(findings, detection_metrics)
            if need_recheck:
                recheck_timeout = int(_to_float(os.getenv("ADAPTIVE_RECHECK_TIMEOUT_SEC", "240"), 240.0))
                recheck_recursion_limit = int(
                    _to_float(os.getenv("ADAPTIVE_RECHECK_RECURSION_LIMIT", "24"), 24.0)
                )
                recheck_start = time.time()
                recheck_status = "ok"
                recheck_error = None
                intersection_meta: Dict = {}
                recheck_state = _build_initial_state(challenge, challenge_code)
                recheck_state["messages"] = list(initial_state.get("messages", []) or []) + [
                    HumanMessage(content=_build_recheck_context(challenge, findings))
                ]

                recheck_config: RunnableConfig = {
                    "configurable": dict(runnable_config.get("configurable", {}) or {}),
                    "callbacks": list(runnable_config.get("callbacks", []) or []),
                    "recursion_limit": recheck_recursion_limit,
                    "run_name": f"{challenge_code}-recheck",
                    "metadata": dict(runnable_config.get("metadata", {}) or {}),
                }
                recheck_config["metadata"]["adaptive_recheck"] = True
                recheck_config["metadata"]["adaptive_recheck_reason"] = recheck_reason
                recheck_config["metadata"]["adaptive_recheck_timeout"] = recheck_timeout

                recheck_findings: List[Dict] = []
                recheck_detection_metrics: Dict = {}
                recheck_agent_metrics: Dict[str, int] = {
                    "advisor_rounds": 0,
                    "main_rounds": 0,
                    "poc_rounds": 0,
                    "docker_rounds": 0,
                    "tool_rounds": 0,
                }
                try:
                    log_system_event(
                        "[复检] 触发自适应二次复检",
                        {
                            "challenge_code": challenge_code,
                            "reason": recheck_reason,
                            "timeout_sec": recheck_timeout,
                            "recursion_limit": recheck_recursion_limit,
                        },
                    )
                    async with concurrent_semaphore:
                        async with asyncio.timeout(recheck_timeout):
                            second_state = await app.with_config({"run_name": f"{challenge_code}-recheck"}).ainvoke(
                                recheck_state, recheck_config
                            )
                    recheck_findings = second_state.get("findings", []) or []
                    recheck_findings = _merge_with_working_memory_findings(challenge_code, recheck_findings)
                    recheck_detection_metrics = _build_detection_metrics_from_findings(
                        recheck_findings,
                        time.time() - start_time,
                    )
                    recheck_detection_metrics.update(dict(second_state.get("detection_metrics", {}) or {}))
                    recheck_agent_metrics = _extract_agent_metrics(second_state)
                    intersection_findings, intersection_meta = _intersect_findings(findings, recheck_findings)
                    findings = _merge_with_working_memory_findings(challenge_code, intersection_findings)
                    detection_metrics = _build_detection_metrics_from_findings(
                        findings, time.time() - start_time
                    )
                    detection_metrics["adaptive_recheck"] = {
                        "enabled": True,
                        "trigger_reason": recheck_reason,
                        "status": "ok",
                        "second_pass_findings": len(recheck_findings),
                        "second_pass_confirmed": int(recheck_detection_metrics.get("confirmed_count", 0) or 0),
                        "elapsed_seconds": round(time.time() - recheck_start, 2),
                        "intersection": intersection_meta,
                    }
                    attempts += _extract_execution_attempts(second_state)
                    agent_metrics = _merge_agent_metrics(agent_metrics, recheck_agent_metrics)
                except asyncio.TimeoutError:
                    recheck_status = "timeout"
                    recheck_error = f"adaptive_recheck_timeout_{recheck_timeout}s"
                    log_system_event(
                        "[复检] ⏱️ 二次复检超时，保留首轮结果",
                        {"challenge_code": challenge_code, "timeout_sec": recheck_timeout},
                        level=logging.WARNING,
                    )
                except Exception as recheck_exc:
                    recheck_status = "error"
                    recheck_error = str(recheck_exc)
                    log_system_event(
                        "[复检] ⚠️ 二次复检异常，保留首轮结果",
                        {
                            "challenge_code": challenge_code,
                            "error_type": type(recheck_exc).__name__,
                            "error": str(recheck_exc),
                        },
                        level=logging.WARNING,
                    )
                finally:
                    if "adaptive_recheck" not in detection_metrics:
                        detection_metrics["adaptive_recheck"] = {
                            "enabled": True,
                            "trigger_reason": recheck_reason,
                            "status": recheck_status,
                            "error": recheck_error,
                            "elapsed_seconds": round(time.time() - recheck_start, 2),
                        }
            else:
                detection_metrics = detection_metrics or _build_detection_metrics_from_findings(findings, elapsed_time)
                detection_metrics["adaptive_recheck"] = {
                    "enabled": False,
                    "trigger_reason": recheck_reason,
                    "status": "skipped",
                }

            elapsed_time = time.time() - start_time
            strict_confirmed_count = len(
                [
                    f
                    for f in (findings or [])
                    if (f.get("status") or "").strip().lower() == "confirmed" and bool(f.get("strict_verified"))
                ]
            )
            vulnerability_detected = bool(
                int(detection_metrics.get("confirmed_count", 0) or 0) > 0
                or strict_confirmed_count > 0
                or has_actionable_confirmed_findings(findings)
            )
            if objective_mode == "flag":
                success = bool(flag)
            elif objective_mode == "detect":
                success = vulnerability_detected
            else:
                # hybrid: 检测优先，flag 作为补充输出
                success = vulnerability_detected

            report_md = None
            report_docx = None
            try:
                report_md = save_report_files(
                    challenge=challenge,
                    result={
                        "success": success,
                        "objective_mode": objective_mode,
                        "vulnerability_detected": vulnerability_detected,
                        "findings": findings,
                        "detection_metrics": detection_metrics,
                        "flag": flag,
                        "attempts": attempts,
                        "elapsed_time": elapsed_time,
                        "agent_metrics": agent_metrics,
                        "error": None,
                    }
                )
                report_docx = str(Path(report_md).with_suffix(".docx")) if report_md else None
                log_system_event(
                    "[报告] 已生成渗透测试报告",
                    {"markdown": report_md, "docx": report_docx}
                )
            except Exception as report_error:
                log_system_event(
                    f"[报告] ⚠️ 生成报告失败: {str(report_error)}",
                    level=logging.WARNING
                )

            # ⭐ 提取尝试摘要
            attempt_summary = retry_strategy.extract_attempt_summary(
                final_state, strategy_description
            ) if retry_strategy else None
            final_state["findings"] = findings
            final_state["detection_metrics"] = detection_metrics
            final_state["vulnerability_detected"] = vulnerability_detected
            final_state["execution_attempts"] = attempts
            persist_working_memory(final_state)

            if success:
                log_system_event(
                    f"[解题] ✅ 成功: {challenge_code}",
                    {
                        "flag": flag,
                        "findings_count": len(findings),
                        "attempts": attempts,
                        "agent_metrics": agent_metrics,
                        "elapsed": f"{elapsed_time:.1f}s",
                        "strategy": strategy_description,
                        "objective_mode": objective_mode
                    }
                )
                await task_manager.remove_task(challenge_code, success=True, attempt_summary=attempt_summary)
                return {
                    "code": challenge_code,
                    "flag": flag,
                    "findings": findings,
                    "vulnerability_detected": vulnerability_detected,
                    "detection_metrics": detection_metrics,
                    "agent_metrics": agent_metrics,
                    "report_markdown": report_md,
                    "report_docx": report_docx,
                    "score": points,  # 假设满分
                    "attempts": attempts,
                    "success": True,
                    "objective_mode": objective_mode,
                    "elapsed_time": elapsed_time
                }
            else:
                auth_error = None
                explicit_error = final_state.get("error")
                if explicit_error and is_authentication_error(explicit_error):
                    auth_error = explicit_error

                log_system_event(
                    f"[解题] ❌ 失败: {challenge_code}",
                    {
                        "attempts": attempts,
                        "findings_count": len(findings),
                        "agent_metrics": agent_metrics,
                        "elapsed": f"{elapsed_time:.1f}s",
                        "strategy": strategy_description,
                        "objective_mode": objective_mode
                    }
                )
                await task_manager.remove_task(challenge_code, success=False, attempt_summary=attempt_summary)
                return {
                    "code": challenge_code,
                    "flag": None,
                    "findings": findings,
                    "vulnerability_detected": vulnerability_detected,
                    "detection_metrics": detection_metrics,
                    "agent_metrics": agent_metrics,
                    "report_markdown": report_md,
                    "report_docx": report_docx,
                    "score": 0,
                    "attempts": attempts,
                    "success": False,
                    "error": auth_error,
                    "objective_mode": objective_mode,
                    "elapsed_time": elapsed_time
                }

        except KeyboardInterrupt:
            # 允许 Ctrl+C 中断整个程序
            log_system_event(
                f"[解题] 🛑 用户中断",
                level=logging.WARNING
            )
            raise
        except Exception as outer_error:
            # 最外层兜底：捕获所有未预期的异常（包括 Agent 构建失败等）
            log_system_event(
                f"[解题] 🚨 严重异常: {challenge_code} - {str(outer_error)}",
                level=logging.CRITICAL
            )
            persist_working_memory(initial_state, error=f"critical_error: {str(outer_error)}")
            await task_manager.remove_task(challenge_code, success=False)
            return {
                "code": challenge_code,
                "flag": None,
                "score": 0,
                "attempts": 0,
                "success": False,
                "error": f"critical_error: {str(outer_error)}",
                "elapsed_time": 0
            }
    finally:
        # ⭐ 确保清除题目上下文（无论成功、失败还是异常）
        clear_challenge_context()


