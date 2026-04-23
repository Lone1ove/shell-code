"""
Prompt 模板集合。

集中管理 Advisor / Main Agent 的上下文构建与提示词文本。
"""

import os
from typing import Any, Dict, List


TOOL_OUTPUT_SUMMARY_PROMPT = """
请将工具输出压缩成面向后续决策的短摘要。

强制规则：
1. 必须区分“工具执行成功”和“漏洞验证成功”，不要混淆。
2. 如果原文包含 PASS / FAIL / not vulnerable / blocked / no runtime output / rejected 等明确结论，必须保留。
3. 如果只有脚本执行成功、Exit Code: 0、HTTP 200，但没有确定性证据，不得写成验证成功。
4. 优先保留：目标、payload、状态码、确定性运行时证据、负向证据、结论。

输出格式：
1. Tool execution status
2. Verification verdict
3. Deterministic evidence
4. Negative evidence
5. Next-step implication

只输出摘要正文，不要添加额外解释。
"""


ADVISOR_SYSTEM_PROMPT = """
你是 CTF/Web 渗透测试顾问 Advisor。
你的职责：
1. 分析主攻手当前进展与失败原因。
2. 提供明确、可执行、低风险且高价值的下一步建议。
3. 建议优先使用 execute_python_poc 或 execute_command。
请避免空泛建议，聚焦可落地动作。
"""


MAIN_AGENT_PLANNER_PROMPT = """
你是渗透测试主控 Agent。

规则：
1. 必须基于已有证据制定下一步行动。
2. 每轮只输出一个最有价值的动作，并保持目标聚焦。
3. 优先做“可验证”的最小动作，先验证再扩展。
4. 未出现明确进展前，避免大范围高噪声扫描（如目录爆破、全端口扫描、批量工具轰炸）。
5. 对于同产品家族的相近 CVE，不得混用结论；必须提供向量级区分证据。
6. 只有拿到可复现实证（运行时输出/确定性回显）才可进入 confirmed 思路。

如果需要分发执行任务，使用：
[DISPATCH_TASK]
agent: poc  # 或 docker
task: |
  具体要执行的任务
[/DISPATCH_TASK]

如果需要请求顾问帮助，使用：
[REQUEST_ADVISOR_HELP]

仅在 flag 模式且确认可提交时使用：
[SUBMIT_FLAG:flag{{...}}]

执行偏好：
- 优先输出“单假设、单验证”任务。
- 任务中要明确 PASS/FAIL 判定标准与所需证据。
- 若当前证据冲突或不足，优先请求顾问复盘而不是盲目换漏洞类型。
- 如果工作记忆显示同一路线已多次失败，必须 pivot 或请求顾问，不得重复相同假设。
- 如果目前仍是 0 次工具执行、但自动侦察已经识别出具体表单/端点，优先给出一个最小可证伪执行任务，而不是继续顾问空转。
- 如果上一路径是传输层/连接层异常中断，但服务连通性已恢复，优先对同一假设做一次最小化重试，再决定是否 pivot。
- 如果上轮只拿到“部分处理迹象 + 无显式成功 + 传输中断/验证未完成”，优先派发一个更严格的单步复检任务，不要直接回顾问空转。
- 不要把本地执行器容器里的 echo/cat/临时文件输出当成目标侧成功证据。
- 如果上下文已经给出“候选入口提示”和“已失败假设”，优先在候选入口之间切换，不要重复已失败假设。

当前上下文：
{current_context}
"""


def _verification_gap_text(item: Dict[str, Any]) -> str:
    checks = dict(item.get("verification_checks") or {})
    missing = [key for key, value in checks.items() if not bool(value)]
    if missing:
        return "missing:" + ",".join(missing)
    audit_note = str(item.get("audit_note") or "").strip()
    if audit_note:
        return audit_note
    return ""


def _append_findings_snapshot(
    context_parts: List[str],
    findings: List[Dict[str, Any]],
    *,
    title: str,
    statuses: set[str],
    limit: int = 4,
) -> None:
    scoped = [
        item for item in findings
        if str(item.get("status") or "").strip().lower() in statuses
    ]
    if not scoped:
        return

    lines = [title]
    for item in scoped[:limit]:
        status = str(item.get("status") or "unknown").lower()
        vuln_type = str(item.get("vuln_type") or "unknown")
        cve = str(item.get("cve") or "N/A")
        score = float(item.get("score") or item.get("confidence") or 0.0)
        gap = _verification_gap_text(item)
        checks = dict(item.get("verification_checks") or {})
        check_text = ", ".join([f"{k}={bool(v)}" for k, v in checks.items()]) if checks else "N/A"
        lines.append(f"- [{status}] {vuln_type} | cve={cve} | score={score:.3f} | gap={gap or 'none'}")
        lines.append(f"  checks: {check_text}")
        evidence = str(item.get("evidence") or "").strip()
        if evidence:
            lines.append(f"  evidence: {evidence[:220]}")
    context_parts.append("\n".join(lines))


def _execution_attempts(state: Dict[str, Any]) -> int:
    explicit = int(state.get("execution_attempts", 0) or 0)
    if explicit > 0:
        return explicit
    return int(state.get("tool_rounds", 0) or 0)


def _execution_outcome_lines(state: Dict[str, Any]) -> List[str]:
    outcome = dict(state.get("last_execution_outcome") or {})
    if not outcome:
        return []
    lines = ["## 最近执行结果"]
    lines.append(f"- 工具状态: {outcome.get('tool_status', 'unknown')}")
    lines.append(f"- 验证状态: {outcome.get('verification_status', 'unknown')}")
    lines.append(f"- 进展级别: {outcome.get('progress_status', 'unknown')}")
    lines.append(f"- 统一结论: {outcome.get('summary', 'N/A')}")
    if outcome.get("should_retry_same_hypothesis"):
        lines.append("- 路由建议: 优先做同假设的一次更严格复检")
    return lines


def _dedup_state_strings(items: List[Any], *, limit: int) -> List[str]:
    values: List[str] = []
    seen = set()
    for item in list(items or []):
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(text)
    return values[-limit:]


def _filtered_action_history(state: Dict[str, Any], *, limit: int, compact: bool = False) -> List[str]:
    tool_rounds = int(state.get("tool_rounds", 0) or 0)
    filtered: List[str] = []
    for item in list(state.get("action_history") or []):
        text = str(item).strip()
        if not text:
            continue
        lower = text.lower()
        if (
            "forced advisor review" in lower
            or "advisor_loop_limit" in lower
            or "converged_without_action" in lower
            or lower.startswith("[executionoutcome]")
            or lower.startswith("[strategyswitch]")
        ):
            continue
        filtered.append(text)

    if compact and tool_rounds == 0:
        dispatch_or_finding = [
            item for item in filtered
            if "dispatch ->" in item.lower() or item.lower().startswith("[finding/")
        ]
        if dispatch_or_finding:
            return dispatch_or_finding[-limit:]
        hypothesis_only = [
            item for item in filtered
            if item.lower().startswith("[hypothesis/")
        ]
        return hypothesis_only[-min(limit, 2):]

    return filtered[-limit:]


def build_advisor_context(state: Dict[str, Any], *, compact: bool = False) -> List[str]:
    """构建给 Advisor 的上下文片段。"""
    context_parts: List[str] = []

    messages = state.get("messages", [])
    if messages:
        first_msg = messages[0]
        content = getattr(first_msg, "content", "")
        if isinstance(content, str) and "系统自动侦察结果" in content:
            context_parts.append(f"## 自动侦察结果\n\n{content}")

    challenge = state.get("current_challenge") or {}
    if challenge:
        target_info = challenge.get("target_info", {})
        ip = target_info.get("ip", "unknown")
        ports = target_info.get("port", [])
        code = challenge.get("challenge_code", challenge.get("code", "unknown"))
        hint_content = challenge.get("hint_content", "")
        attempts = _execution_attempts(state)
        display_url = challenge.get("_target_url", f"http://{ip}:{','.join(map(str, ports)) if ports else '80'}")
        execution_url = challenge.get("_execution_target_url", display_url)

        block = [
            "## 目标信息",
            f"- 题号: {_display_challenge_code(challenge, code)}",
            f"- 展示目标: {display_url}",
            f"- 实际执行地址: {execution_url}",
            f"- 已尝试次数: {attempts}",
            "- 注意: 实际执行地址是容器/执行层的访问映射，不代表目标主机错误。",
        ]
        if hint_content:
            block.append(f"- 提示: {hint_content}")
        context_parts.append("\n".join(block))

    findings = state.get("findings", []) or []
    if findings:
        summary_lines = ["## 当前发现审稿视图"]
        for item in findings[:6]:
            status = str(item.get("status") or "unknown").lower()
            vuln_type = str(item.get("vuln_type") or "unknown")
            cve = str(item.get("cve") or "N/A")
            template_id = str(item.get("template_id") or "N/A")
            summary_lines.append(
                f"- [{status}] {vuln_type} | cve={cve} | template={template_id} | strict_verified={bool(item.get('strict_verified', False))}"
            )
        context_parts.append("\n".join(summary_lines))
        _append_findings_snapshot(
            context_parts,
            findings,
            title="## 近期被拒绝/待降级项",
            statuses={"rejected"},
            limit=3,
        )
        _append_findings_snapshot(
            context_parts,
            findings,
            title="## 近期仍需补证的疑似项",
            statuses={"suspected"},
            limit=3,
        )

    review_state = [
        "## 复盘状态",
        f"- 真实执行尝试次数: { _execution_attempts(state) }",
        f"- 连续失败次数: {int(state.get('consecutive_failures', 0) or 0)}",
        f"- 无进展轮次: {int(state.get('no_progress_rounds', 0) or 0)}",
        f"- 重复任务轮次: {int(state.get('repeated_task_rounds', 0) or 0)}",
        f"- 重复假设轮次: {int(state.get('repeated_hypothesis_rounds', 0) or 0)}",
        f"- 顾问空转轮次: {int(state.get('advisor_loop_rounds', 0) or 0)}",
        f"- 当前假设签名: {state.get('last_hypothesis_signature') or 'N/A'}",
    ]
    context_parts.append("\n".join(review_state))
    outcome_lines = _execution_outcome_lines(state)
    if outcome_lines:
        context_parts.append("\n".join(outcome_lines))

    candidate_surfaces = _dedup_state_strings(state.get("candidate_surface_hints") or [], limit=8)
    if candidate_surfaces:
        context_parts.append("## 候选入口提示\n\n" + "\n".join([f"- {item}" for item in candidate_surfaces]))

    blocked_hypotheses = _dedup_state_strings(state.get("blocked_hypothesis_signatures") or [], limit=6)
    if blocked_hypotheses:
        context_parts.append("## 已失败假设（不要直接重复）\n\n" + "\n".join([f"- {item}" for item in blocked_hypotheses]))

    action_history = _filtered_action_history(state, limit=8 if compact else 10, compact=compact)
    if action_history:
        formatted = "\n".join([f"{i}. {a}" for i, a in enumerate(action_history[-10:], 1)])
        context_parts.append(f"## 最近操作\n\n{formatted}")

    return context_parts


def build_main_context(
    state: Dict[str, Any],
    *,
    compact: bool = False,
    include_action_history: bool = True,
) -> str:
    """构建给 Main Agent 的上下文字符串。"""
    parts: List[str] = []

    challenge = state.get("current_challenge") or {}
    if challenge:
        target_info = challenge.get("target_info", {})
        ip = target_info.get("ip", "unknown")
        ports = target_info.get("port", [])
        port_str = str(ports[0]) if ports else "80"
        display_url = challenge.get("_target_url", f"http://{ip}:{port_str}")
        execution_url = challenge.get("_execution_target_url", display_url)

        execute_hint = ""
        if execution_url != display_url:
            execute_hint = f"\n- 实际执行 URL: {execution_url}\n- 注意: 实际执行 URL 是容器访问映射，不代表目标主机错误。"

        parts.append(
            "\n".join(
                [
                    "## 当前目标",
                    f"- 题号: {_display_challenge_code(challenge, challenge.get('challenge_code', challenge.get('code', 'unknown')))}",
                    f"- URL: {display_url}{execute_hint}",
                    f"- 提示: {challenge.get('hint_content', '-')}",
                ]
            )
        )

    messages = state.get("messages", [])
    attempts = _execution_attempts(state)
    failures = state.get("consecutive_failures", 0)

    parts.append(
        "\n".join(
            [
                "## 执行状态",
                f"- 真实执行尝试次数: {attempts}",
                f"- 连续失败次数: {failures}",
                f"- 无进展轮次: {int(state.get('no_progress_rounds', 0) or 0)}",
                f"- 重复假设轮次: {int(state.get('repeated_hypothesis_rounds', 0) or 0)}",
                f"- 顾问空转轮次: {int(state.get('advisor_loop_rounds', 0) or 0)}",
                f"- 当前假设签名: {state.get('last_hypothesis_signature') or 'N/A'}",
            ]
        )
    )
    outcome_lines = _execution_outcome_lines(state)
    if outcome_lines:
        parts.append("\n".join(outcome_lines))

    candidate_surfaces = _dedup_state_strings(state.get("candidate_surface_hints") or [], limit=8)
    if candidate_surfaces:
        parts.append("## 候选入口提示\n\n" + "\n".join([f"- {item}" for item in candidate_surfaces]))

    blocked_hypotheses = _dedup_state_strings(state.get("blocked_hypothesis_signatures") or [], limit=6)
    if blocked_hypotheses:
        parts.append("## 已失败假设（禁止直接重复）\n\n" + "\n".join([f"- {item}" for item in blocked_hypotheses]))

    findings = state.get("findings", []) or []
    if findings:
        active_lines = ["## 当前发现快照"]
        finding_limit = 3 if compact else 5
        for item in findings[:finding_limit]:
            status = str(item.get("status") or "unknown").lower()
            vuln_type = str(item.get("vuln_type") or "unknown")
            cve = str(item.get("cve") or "N/A")
            gap = _verification_gap_text(item)
            active_lines.append(f"- [{status}] {vuln_type} | cve={cve} | gap={gap or 'none'}")
        parts.append("\n".join(active_lines))
        _append_findings_snapshot(
            parts,
            findings,
            title="## 最近失败/被拒绝的验证",
            statuses={"rejected"},
            limit=2 if compact else 3,
        )

    action_history = _filtered_action_history(state, limit=3 if compact else 5, compact=compact)
    if include_action_history and action_history:
        parts.append("## 最近操作\n\n" + "\n".join(action_history))

    return "\n\n".join(parts)


def get_target_url(state: Dict[str, Any]) -> str:
    """从状态中获取展示给模型的人类目标 URL。"""
    challenge = state.get("current_challenge") or {}
    explicit_display_url = challenge.get("_target_url")
    if explicit_display_url:
        return explicit_display_url
    target_info = challenge.get("target_info", {})
    ip = target_info.get("ip", "unknown")
    ports = target_info.get("port", [])
    port_str = str(ports[0]) if ports else "80"
    return f"http://{ip}:{port_str}"


def get_execution_url(state: Dict[str, Any]) -> str:
    """从状态中获取执行层应访问的 URL。"""
    challenge = state.get("current_challenge") or {}
    explicit_execution_url = challenge.get("_execution_target_url")
    if explicit_execution_url:
        return explicit_execution_url
    return get_target_url(state)


def get_target_info(state: Dict[str, Any]) -> str:
    """以文本形式返回当前目标信息。"""
    challenge = state.get("current_challenge") or {}
    target_info = challenge.get("target_info", {})

    ip = target_info.get("ip", "unknown")
    ports = target_info.get("port", [])
    execution_host = challenge.get("_execution_host", ip)
    port_text = ", ".join(map(str, ports)) if ports else "unknown"

    if execution_host != ip:
        return f"- IP: {ip}\n- 实际执行主机: {execution_host}\n- 端口: {port_text}"
    return f"- IP: {ip}\n- 端口: {port_text}"


def _benchmark_priors_enabled() -> bool:
    return os.getenv("ENABLE_BENCHMARK_PRIORS", "false").strip().lower() == "true"


def _display_challenge_code(challenge: Dict[str, Any], fallback: str) -> str:
    if challenge.get("_benchmark_target_id") and not _benchmark_priors_enabled():
        return "benchmark_target"
    return str(fallback or "unknown")
