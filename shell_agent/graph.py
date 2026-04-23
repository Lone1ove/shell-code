"""
Shell Agent 三层协作图（V2）。
结构：
- 规划层：Advisor + Main Agent
- 执行层：PoC + Docker Agent
- 能力层：Skills 按需注入
"""

import asyncio
import time
import os
import re
import hashlib
import logging
from urllib.parse import urlparse
from typing import Literal, Optional, Dict, List
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig

from shell_agent.state import PenetrationTesterState
from shell_agent.tools import get_all_tools
from shell_agent.common import (
    count_actionable_findings,
    has_actionable_active_findings,
    has_actionable_confirmed_findings,
    has_strong_verification_signal,
    is_high_value_active_finding,
    log_system_event,
    log_agent_thought,
    normalize_text_content,
)
from shell_agent.langmem_memory import get_memory_store, get_all_memory_tools
from shell_agent.utils.rate_limiter import get_rate_limiter
from shell_agent.utils.util import is_authentication_error, is_context_overflow_error, retry_llm_call
from shell_agent.utils.failure_detector import detect_failure_with_llm
from shell_agent.cve.engine import assess_findings
from shell_agent.graph_findings import (
    _extract_finding_from_text,
    _extract_verified_flag_from_tool_messages,
    _finding_key,
    _looks_like_local_scaffolding_output,
)
from shell_agent.graph_tasks import (
    _focused_verification_task,
    _has_tool_progress_signal,
    _is_connectivity_failure_text,
    _normalize_dispatch_task_target,
    _parse_dispatch_task,
    _stabilize_dispatch_task,
    _task_signature,
)
from shell_agent.working_memory import (
    persist_working_memory,
    load_decision_memory_for_state,
    load_frozen_findings_for_state,
)

# 导入 Agent 提示词
from shell_agent.agents.advisor import ADVISOR_SYSTEM_PROMPT
from shell_agent.agents.main_agent import MAIN_AGENT_SYSTEM_PROMPT
from shell_agent.agents.poc_agent import POC_AGENT_SYSTEM_PROMPT
from shell_agent.agents.docker_agent import DOCKER_AGENT_SYSTEM_PROMPT
from shell_agent.prompts_book import (
    TOOL_OUTPUT_SUMMARY_PROMPT,
    MAIN_AGENT_PLANNER_PROMPT,
    build_advisor_context,
    build_main_context,
    get_execution_url,
    get_target_url,
    get_target_info,
)

# 导入 Skills 相关能力
from shell_agent.skills.skill_loader import load_skills_for_context, get_skill_summary

# 导入 RAG 检索
from shell_agent.rag.retriever import retrieve_wooyun_cases, retrieve_cve_records


def _provider_rps(primary_key: str, legacy_key: str, default: str = "2.0") -> float:
    raw = os.getenv(primary_key, "").strip() or os.getenv(legacy_key, "").strip() or default
    try:
        return float(raw)
    except Exception:
        return float(default)


# 初始化全局速率限制器
MAIN_LLM_RPS = _provider_rps("MAIN_LLM_REQUESTS_PER_SECOND", "DEEPSEEK_REQUESTS_PER_SECOND")
ADVISOR_LLM_RPS = _provider_rps("ADVISOR_LLM_REQUESTS_PER_SECOND", "MINIMAX_REQUESTS_PER_SECOND")

# limiter key names are for observability only; keep provider-agnostic names to avoid confusion.
main_limiter = get_rate_limiter("main_llm", requests_per_second=MAIN_LLM_RPS, burst_size=5)
advisor_limiter = get_rate_limiter("advisor_llm", requests_per_second=ADVISOR_LLM_RPS, burst_size=5)


def _objective_mode() -> str:
    mode = os.getenv("OBJECTIVE_MODE", "hybrid").strip().lower()
    if mode not in {"detect", "flag", "hybrid"}:
        return "hybrid"
    return mode


def _benchmark_priors_enabled() -> bool:
    return os.getenv("ENABLE_BENCHMARK_PRIORS", "false").strip().lower() == "true"


_VULN_SIGNAL_RE = re.compile(
    r"(cve-\d{4}-\d+|漏洞|vulnerab|exploit|payload|ognl|s2-0\d{2}|"
    r"rce|remote code execution|命令执行|远程代码执行|sqli|sql injection|"
    r"xss|ssrf|file inclusion|path traversal|uid=|whoami)",
    re.IGNORECASE,
)

_STRUTS_OGNL_STRONG_SIGNAL_RE = re.compile(
    r"(ognl|s2-045|s2-046|s2-057|cve-2017-5638|cve-2018-11776|"
    r"doupload\.action|content-type:\s*%\{|x-ognl-test|x-cmd-result|x-user-name|"
    r"namespace=|actionchain)",
    re.IGNORECASE,
)


def _infer_skill_stage(state: PenetrationTesterState, context_text: str) -> str:
    tool_rounds = int(state.get("tool_rounds", 0) or 0)
    findings = state.get("findings") or []
    actionable_counts = count_actionable_findings(findings)
    vuln_detected = bool(state.get("vulnerability_detected", False)) or actionable_counts.get("confirmed", 0) > 0
    active_findings = actionable_counts.get("confirmed", 0) > 0 or actionable_counts.get("suspected", 0) > 0
    last_execution_outcome = dict(state.get("last_execution_outcome") or {})
    last_tool_status = str(last_execution_outcome.get("tool_status") or "").strip().lower()
    last_verification_status = str(last_execution_outcome.get("verification_status") or "").strip().lower()
    last_summary = str(last_execution_outcome.get("summary") or "").strip().lower()
    candidate_surfaces = list(state.get("candidate_surface_hints") or [])
    has_signal = bool(_VULN_SIGNAL_RE.search(context_text or ""))

    if tool_rounds <= 0 and not active_findings and not vuln_detected:
        return "recon"
    if active_findings or vuln_detected:
        return "vuln"
    if (
        "surface" in last_summary
        or last_verification_status == "inconclusive"
        or last_tool_status in {"partial", "failure", "transport_error"}
        or candidate_surfaces
    ):
        return "transition"
    if tool_rounds <= 1 and not has_signal:
        return "recon"
    if tool_rounds > 0 and has_signal:
        return "transition"
    if has_signal:
        return "transition"
    return "transition"


def _is_family_specific_hypothesis_signature(signature: str) -> bool:
    raw = str(signature or "").strip().lower()
    if not raw:
        return False
    family = raw.split(":", 1)[0].strip()
    return family not in {"", "recon"}


def _extract_recon_surface_hints_from_messages(state: PenetrationTesterState, *, limit: int = 12) -> List[str]:
    hints: List[str] = []
    messages = list(state.get("messages") or [])
    if not messages:
        return hints

    for msg in messages[:8]:
        content = normalize_text_content(getattr(msg, "content", ""))
        if not content:
            continue
        lower = content.lower()
        # Prioritize auto-recon and form/action rich context to avoid noisy extraction.
        if not any(
            marker in lower
            for marker in [
                "自动侦察",
                "auto recon",
                "form",
                "action:",
                "action=\"/",
                "doupload.action",
                "struts2",
            ]
        ):
            continue

        for candidate in re.findall(r"action\s*[:=]\s*`?([/\w.\-;?=&%]+)`?", content, flags=re.IGNORECASE):
            normalized = _normalize_surface_hint(candidate)
            if normalized:
                hints.append(normalized)
        for candidate in re.findall(r'action=["\']([/\w.\-;?=&%]+)["\']', content, flags=re.IGNORECASE):
            normalized = _normalize_surface_hint(candidate)
            if normalized:
                hints.append(normalized)
        for candidate in re.findall(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+)", content):
            normalized = _normalize_surface_hint(candidate)
            if normalized:
                hints.append(normalized)

    return _merge_unique_state_strings([], hints, limit=limit)


def _collect_family_signal_context(state: PenetrationTesterState) -> str:
    challenge = dict(state.get("current_challenge") or {})
    parts: List[str] = [
        str(challenge.get("hint_content") or ""),
        str(challenge.get("_target_url") or ""),
        str(challenge.get("_execution_target_url") or ""),
        str(challenge.get("_expected_family") or ""),
        " ".join(str(x) for x in (challenge.get("_expected_cves") or []) if x),
        "\n".join(str(x) for x in (state.get("candidate_surface_hints") or []) if x),
        "\n".join(_extract_recon_surface_hints_from_messages(state, limit=12)),
        "\n".join(str(x) for x in list(state.get("action_history") or [])[-12:] if x),
    ]
    for msg in list(state.get("messages") or [])[:6]:
        content = normalize_text_content(getattr(msg, "content", ""))
        if content:
            parts.append(_truncate_text_for_prompt(content, 1200))
    return normalize_text_content("\n".join(parts))


def _should_preserve_family_specific_task(state: PenetrationTesterState, hypothesis_signature: str) -> bool:
    raw = str(hypothesis_signature or "").strip().lower()
    if not raw:
        return False

    family = raw.split(":", 1)[0].strip()
    path_hint = raw.split(":", 1)[1].strip() if ":" in raw else ""
    signal_context = _collect_family_signal_context(state).lower()
    family_markers = {
        "struts2-ognl": ["struts2", "ognl", "s2-045", "s2-057", "x-cmd-result", "x-user-name", "doupload.action"],
        "rce": ["remote code execution", "command execution", "uid=", "whoami", "gid="],
        "ssti": ["ssti", "template injection", "jinja", "{{", "${"],
        "sqli": ["sql injection", "union select", "sleep(", "benchmark(", "sql syntax"],
        "xss": ["xss", "<script", "onerror=", "javascript:"],
        "ssrf": ["ssrf", "169.254.169.254", "metadata", "gopher://"],
        "xxe": ["xxe", "<!entity", "external entity", "dtd"],
        "file-upload": ["multipart/form-data", "filename=", "content-disposition", "upload", "form"],
        "auth-bypass": ["auth bypass", "unauthorized", "jwt", "session", "token bypass"],
        "file-inclusion": ["file inclusion", "../", "..%2f", "/etc/passwd", "path traversal"],
    }

    markers = family_markers.get(family, [family] if family else [])
    marker_hits = sum(1 for marker in markers if marker and marker in signal_context)
    path_supported = bool(path_hint and path_hint in signal_context)

    action_hints = _extract_recon_surface_hints_from_messages(state, limit=12) + [
        str(x) for x in (state.get("candidate_surface_hints") or [])
    ]
    normalized_action_hints = [(_normalize_surface_hint(x) or str(x).strip().lower()) for x in action_hints if str(x).strip()]
    hint_support = 0
    if path_hint and any(path_hint in item for item in normalized_action_hints):
        hint_support += 1
    if any(marker in item for marker in [".action", ".jsp", ".php", "/api/", "/upload", "/login"] for item in normalized_action_hints):
        hint_support += 1

    if family == "struts2-ognl":
        marker_hits += 1 if bool(_STRUTS_OGNL_STRONG_SIGNAL_RE.search(signal_context)) else 0

    # Generic family fallback: allow preserving when benchmark priors explicitly indicate
    # the same family in manual/benchmark challenge metadata.
    expected_family = str((state.get("current_challenge") or {}).get("_expected_family") or "").strip().lower()
    expected_support = 1 if expected_family and family and family in expected_family else 0

    score = marker_hits + hint_support + expected_support + (1 if path_supported else 0)
    return score >= 2


def _should_enable_rag(state: PenetrationTesterState, skill_stage: str, full_signal_context: str) -> bool:
    enabled = os.getenv("ENABLE_WOOYUN_RAG", "true").strip().lower() == "true"
    if not enabled:
        return False

    if skill_stage == "recon":
        return False

    challenge = state.get("current_challenge") or {}
    expected_cves = challenge.get("_expected_cves") or []
    if _benchmark_priors_enabled() and expected_cves:
        return True

    signal_hits = len(set(re.findall(_VULN_SIGNAL_RE, full_signal_context or "")))
    return signal_hits >= 2


def _normalize_cve_token(value: str) -> str:
    token = str(value or "").strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", token):
        return token
    return ""


def _extract_cve_tokens_from_text(text: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", str(text or ""), flags=re.IGNORECASE):
        normalized = _normalize_cve_token(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


_CVE_FAMILY_HINTS = {
    "struts2": ["struts", "struts2", "ognl", "s2-045", "s2-046", "s2-057", "doupload.action"],
    "tomcat": ["tomcat", "webdav", ".jsp", "put /"],
    "weblogic": ["weblogic", "wls-wsat", "t3"],
    "spring": ["spring", "spring4shell", "class.module.classloader"],
    "log4j": ["log4j", "log4shell", "jndi"],
    "confluence": ["confluence", "atlassian"],
    "shiro": ["shiro", "rememberme"],
    "fastjson": ["fastjson", "autotype"],
}


def _infer_family_hint(text: str) -> str:
    lower = str(text or "").lower()
    for family, aliases in _CVE_FAMILY_HINTS.items():
        if any(alias in lower for alias in aliases):
            return family
    return ""


def _compact_cve_query_context(text: str, *, max_chars: int = 900) -> str:
    normalized = normalize_text_content(text or "")
    if not normalized:
        return ""
    keep_markers = [
        "cve-",
        "struts",
        "ognl",
        "content-type",
        "multipart",
        "x-ognl",
        "x-cmd",
        "x-user-name",
        "uid=",
        "gid=",
        "whoami",
        "doUpload.action".lower(),
        "verdict:",
        "result:",
        "not vulnerable",
        "blocked",
        "incomplete",
        "chunkedencodingerror",
    ]
    drop_markers = [
        "<html",
        "<body",
        "powered by jetty",
        "http error",
        "stack trace",
        "traceback",
        "${(111+111)}",
        "%{(111+111)}",
        "grep -o \"222\"",
        "grep -o '222'",
    ]
    out_lines: List[str] = []
    seen = set()
    for raw_line in normalized.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lower = line.lower()
        if any(marker in lower for marker in drop_markers):
            continue
        if not any(marker in lower for marker in keep_markers):
            continue
        if lower in seen:
            continue
        seen.add(lower)
        out_lines.append(line)
        if len("\n".join(out_lines)) >= max_chars:
            break
    if not out_lines:
        out_lines = [line.strip() for line in normalized.splitlines()[:6] if line.strip()]
    compact = "\n".join(out_lines)
    return compact[:max_chars]


def _build_cve_focus_query(
    state: PenetrationTesterState,
    *,
    hint_and_context: str,
    recent_tool_context: str,
) -> str:
    parts: List[str] = []
    target = str(get_execution_url(state) or get_target_url(state) or "").strip()
    if target:
        parts.append(target)
    if hint_and_context:
        parts.append(hint_and_context)
    if recent_tool_context:
        compact_tool_context = _compact_cve_query_context(recent_tool_context, max_chars=900)
        if compact_tool_context:
            parts.append(compact_tool_context)

    hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip()
    if hypothesis_signature:
        parts.append(hypothesis_signature)

    for surface in list(state.get("candidate_surface_hints") or [])[-8:]:
        text = str(surface or "").strip()
        if text:
            parts.append(text)

    ranked_findings = sorted(
        [f for f in list(state.get("findings") or []) if isinstance(f, dict)],
        key=lambda row: float(row.get("score") or row.get("confidence") or 0.0),
        reverse=True,
    )
    for finding in ranked_findings[:3]:
        parts.extend(
            [
                str(finding.get("vuln_type") or ""),
                str(finding.get("template_id") or ""),
                str(finding.get("product_family") or ""),
                str(finding.get("cve") or ""),
                " ".join(str(x) for x in (finding.get("cve_candidates") or [])[:4]),
                str(finding.get("evidence") or "")[:300],
            ]
        )

    challenge = dict(state.get("current_challenge") or {})
    parts.extend(
        [
            " ".join(str(x) for x in (challenge.get("_expected_cves") or []) if str(x).strip()),
            str(challenge.get("_expected_family") or ""),
        ]
    )
    normalized = normalize_text_content(" ".join(part for part in parts if str(part).strip()))
    return normalized[:1800]


def _load_cve_focus_candidates(
    state: PenetrationTesterState,
    *,
    hint_and_context: str,
    recent_tool_context: str,
    max_candidates: int = 3,
) -> List[Dict]:
    if os.getenv("ENABLE_CVE_TASK_GUIDANCE", "true").strip().lower() != "true":
        return []
    findings = list(state.get("findings") or [])
    has_active_findings = has_actionable_active_findings(findings)
    hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip()
    signal_context = normalize_text_content(
        f"{hint_and_context}\n{recent_tool_context}\n{hypothesis_signature}"
    )
    signal_hits = len(set(re.findall(_VULN_SIGNAL_RE, signal_context or "")))
    challenge = dict(state.get("current_challenge") or {})
    benchmark_has_expected = bool(_benchmark_priors_enabled() and (challenge.get("_expected_cves") or []))
    if (
        not has_active_findings
        and signal_hits < 2
        and not _is_family_specific_hypothesis_signature(hypothesis_signature)
        and not benchmark_has_expected
    ):
        return []
    query = _build_cve_focus_query(
        state,
        hint_and_context=hint_and_context,
        recent_tool_context=recent_tool_context,
    )
    if not query:
        return []

    min_severity = (
        os.getenv("CVE_TASK_GUIDANCE_MIN_SEVERITY", "").strip().lower()
        or os.getenv("CVE_RAG_MIN_SEVERITY", "low").strip().lower()
        or "low"
    )
    fetch_top_k = max(
        max_candidates,
        int(os.getenv("CVE_TASK_GUIDANCE_FETCH_TOP_K", "6")),
    )
    try:
        records = retrieve_cve_records(query, top_k=fetch_top_k, min_severity=min_severity)
    except Exception as exc:
        log_system_event(
            "[CVE Guidance] retrieve_cve_records failed",
            {"error": str(exc)},
            level=logging.WARNING,
        )
        return []

    explicit_cves = set(_extract_cve_tokens_from_text(query))
    preferred_family = _infer_family_hint(query)
    ordered_records = list(records)
    if preferred_family:
        family_first = [
            item for item in ordered_records
            if str(item.get("product_family") or "").strip().lower() == preferred_family
        ]
        if family_first:
            others = [
                item for item in ordered_records
                if str(item.get("product_family") or "").strip().lower() != preferred_family
            ]
            ordered_records = family_first + others
    rows: List[Dict] = []
    seen = set()
    for record in ordered_records:
        cve_id = _normalize_cve_token(str(record.get("id") or record.get("cve_id") or ""))
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        default_probe = str(record.get("default_probe") or "").strip()
        confirm_markers = [str(x).strip() for x in (record.get("confirm_markers") or []) if str(x).strip()]
        references = [str(x).strip() for x in (record.get("references") or []) if str(x).strip()]
        if not default_probe and not confirm_markers and not references and cve_id not in explicit_cves:
            continue
        rows.append(
            {
                "cve": cve_id,
                "product_family": str(record.get("product_family") or "unknown").strip().lower(),
                "default_probe": default_probe,
                "confirm_markers": confirm_markers[:6],
                "references": references[:6],
                "severity": str(record.get("severity") or "unknown").strip().lower(),
            }
        )
        if len(rows) >= max_candidates:
            break

    if rows:
        log_system_event(
            "[CVE Guidance] Selected CVE candidates from RAG/intel",
            {
                "query_preview": _truncate_text_for_prompt(query, 180),
                "candidates": [item.get("cve") for item in rows],
            },
        )
    return rows


def _format_cve_focus_candidates(candidates: List[Dict], *, max_chars: int = 900) -> str:
    if not candidates:
        return ""
    lines: List[str] = [
        "## CVE Focus (RAG/Intel)",
        "Prioritize verification from this shortlist before broad trial-and-error:",
    ]
    for idx, row in enumerate(candidates[:4], 1):
        cve = str(row.get("cve") or "N/A")
        family = str(row.get("product_family") or "unknown")
        severity = str(row.get("severity") or "unknown")
        lines.append(f"{idx}) {cve} | family={family} | severity={severity}")
        probe = str(row.get("default_probe") or "").strip()
        if probe:
            lines.append(f"   probe: {probe[:200]}")
        markers = [str(x).strip() for x in (row.get("confirm_markers") or []) if str(x).strip()]
        if markers:
            lines.append("   confirm_markers: " + ", ".join(markers[:5]))
    text = "\n".join(lines)
    return _truncate_text_for_prompt(text, max_chars)


def _build_cve_guided_verification_task(
    state: PenetrationTesterState,
    cve_candidates: List[Dict],
    *,
    prefer_transport_resilient: bool = False,
) -> Optional[Dict]:
    if not cve_candidates:
        return None
    top = dict(cve_candidates[0] or {})
    cve = str(top.get("cve") or "").strip().upper()
    if not cve:
        return None
    target = get_execution_url(state) or get_target_url(state) or "target"
    surface_hint = _pick_candidate_surface_hint(state) or "/"
    action_path = surface_hint if str(surface_hint).startswith("/") else f"/{surface_hint}"
    canonical_action_path = action_path.split(";", 1)[0] or action_path
    family = str(top.get("product_family") or "unknown").strip().lower()
    probe = str(top.get("default_probe") or "").strip()
    markers = [str(x).strip() for x in (top.get("confirm_markers") or []) if str(x).strip()]

    task_text = (
        f"Target: {target}\n"
        f"CVE priority: {cve}\n"
        f"Product family hint: {family or 'unknown'}\n"
        f"Primary action endpoint: {action_path}\n"
        "Run ONE deterministic CVE-focused verification task.\n"
        "Hard constraints:\n"
        f"1) Use `{action_path}` as primary path (optional canonical fallback `{canonical_action_path}` only).\n"
        "2) Keep exactly one exploit hypothesis in this round.\n"
        "3) First capture baseline evidence, then run exploit payload, and compare deterministically.\n"
        "4) Print request target, vector/payload, status code, and short response/header evidence.\n"
        "5) PASS only with deterministic runtime evidence; FAIL if deterministic evidence is absent.\n"
        "6) Output exactly one final verdict line: VERDICT: PASS or VERDICT: FAIL.\n"
    )
    if probe:
        task_text += f"7) Candidate probe hint: {probe}\n"
    if markers:
        task_text += "8) Prefer confirm markers: " + ", ".join(markers[:6]) + "\n"
    if family == "struts2":
        task_text += (
            "9) Struts2-specific constraint: do NOT rely on arithmetic echo checks (for example 111+111 => 222).\n"
            "10) Prefer header-marker verification chain: baseline response must not contain marker header, "
            "then exploit request should add a unique response header marker (for example X-OGNL-Verify).\n"
            "11) If header-marker path fails, try one command-output marker path (uid=/whoami) and stop.\n"
        )
    if prefer_transport_resilient:
        task_text += (
            "12) Transport resilience required: if request fails with connection/read errors "
            "(e.g., IncompleteRead, RemoteDisconnected), retry the SAME request up to 3 times "
            "with short backoff before concluding FAIL.\n"
        )
    return {"agent": "poc", "task": task_text}


def _truncate_text_for_prompt(text: str, max_chars: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if max_chars <= 0 or len(text) <= max_chars:
        return text

    head = int(max_chars * 0.75)
    tail = max_chars - head - 120
    if tail < 0:
        tail = 0
    omitted = len(text) - (head + tail)
    return (
        text[:head]
        + f"\n\n...[TRUNCATED FOR PROMPT, omitted {omitted} chars]...\n\n"
        + (text[-tail:] if tail > 0 else "")
    )


def _should_load_struts_ognl_skill(
    *,
    hint_and_context: str,
    recent_tool_context: str,
    findings: List[Dict],
    last_execution_outcome: Optional[Dict] = None,
    blocked_families: Optional[set[str]] = None,
) -> bool:
    blocked_families = set(blocked_families or set())
    has_actionable_family_finding = has_actionable_active_findings(findings or [])
    latest_outcome = dict(last_execution_outcome or {})
    latest_tool_status = str(latest_outcome.get("tool_status") or "").strip().lower()
    latest_verification_status = str(latest_outcome.get("verification_status") or "").strip().lower()
    latest_summary = str(latest_outcome.get("summary") or "").strip().lower()
    recent_lower = normalize_text_content(recent_tool_context or "").lower()
    hint_lower = normalize_text_content(hint_and_context or "").lower()
    if (
        not findings
        and latest_tool_status in {"partial", "failure", "inconclusive"}
        and latest_verification_status == "inconclusive"
        and "surface" in latest_summary
    ):
        return False

    family_findings = [
        finding
        for finding in findings or []
        if str(finding.get("template_id") or "").strip().lower() == "struts2_ognl_family"
        or str(finding.get("cve") or "").strip().upper() in {"CVE-2017-5638", "CVE-2018-11776"}
        or any(
            str(item).strip().upper() in {"CVE-2017-5638", "CVE-2018-11776"}
            for item in (finding.get("cve_candidates") or [])
        )
    ]
    exploit_level_markers = [
        "x-ognl-test",
        "x-cmd-result",
        "x-user-name",
        "response header injection successful",
        "command execution successful",
        "uid=",
        "gid=",
        "content-type: %{",
        "ognl evaluation detected",
        "ognl injection successful",
        "namespace manipulation successful",
        "action chain bypass successful",
        "cve-2017-5638",
        "cve-2018-11776",
        "s2-045",
        "s2-046",
        "s2-057",
    ]
    has_exploit_level_signal = any(marker in recent_lower for marker in exploit_level_markers) or any(
        marker in hint_lower for marker in ["cve-2017-5638", "cve-2018-11776", "s2-045", "s2-046", "s2-057"]
    )

    if (
        not has_actionable_family_finding
        and blocked_families
        and latest_tool_status in {"failure", "partial", "inconclusive", "transport_error"}
        and not has_exploit_level_signal
    ):
        return False
    if "struts2-ognl" in blocked_families:
        reusable_family_findings = [
            finding
            for finding in family_findings
            if has_actionable_confirmed_findings([finding]) or is_high_value_active_finding(finding)
        ]
        if not reusable_family_findings:
            return False

    for finding in family_findings:
        template_id = str(finding.get("template_id") or "").strip().lower()
        cve = str(finding.get("cve") or "").strip().upper()
        candidates = [str(x).strip().upper() for x in (finding.get("cve_candidates") or []) if x]
        if template_id == "struts2_ognl_family":
            return True
        if cve in {"CVE-2017-5638", "CVE-2018-11776"}:
            return True
        if any(item in {"CVE-2017-5638", "CVE-2018-11776"} for item in candidates):
            return True

    strong_signal_basis = "\n".join(
        [
            _truncate_text_for_prompt(recent_tool_context, 3000),
            _truncate_text_for_prompt(hint_and_context, 1200),
        ]
    )
    negative_basis = strong_signal_basis.lower()
    if any(
        marker in negative_basis
        for marker in [
            "verdict: fail",
            "not vulnerable",
            "未检测到",
            "未发现",
            "target does not appear vulnerable",
            "no command execution detected",
            "no ognl evaluation detected",
        ]
    ):
        return False
    if has_actionable_family_finding:
        return True
    return has_exploit_level_signal


def _normalize_ai_message_content(message: AIMessage) -> AIMessage:
    content = normalize_text_content(getattr(message, "content", ""))
    if content == getattr(message, "content", ""):
        return message
    if hasattr(message, "model_copy"):
        return message.model_copy(update={"content": content})
    if hasattr(message, "copy"):
        return message.copy(update={"content": content})
    return AIMessage(
        content=content,
        tool_calls=list(getattr(message, "tool_calls", []) or []),
        additional_kwargs=dict(getattr(message, "additional_kwargs", {}) or {}),
        response_metadata=dict(getattr(message, "response_metadata", {}) or {}),
        name=getattr(message, "name", None),
        id=getattr(message, "id", None),
    )


def _normalize_message_content(message):
    content = normalize_text_content(getattr(message, "content", ""))
    if content == getattr(message, "content", ""):
        return message
    if hasattr(message, "model_copy"):
        return message.model_copy(update={"content": content})
    if hasattr(message, "copy"):
        return message.copy(update={"content": content})
    if isinstance(message, ToolMessage):
        return ToolMessage(
            content=content,
            tool_call_id=getattr(message, "tool_call_id", ""),
            name=getattr(message, "name", None),
        )
    if isinstance(message, AIMessage):
        return _normalize_ai_message_content(message)
    if isinstance(message, HumanMessage):
        return HumanMessage(content=content)
    if isinstance(message, SystemMessage):
        return SystemMessage(content=content)
    return message


def _task_budget_snapshot(state: PenetrationTesterState) -> Dict[str, float]:
    from shell_agent.core.constants import AgentConfig

    total = float(AgentConfig.get_single_task_timeout())
    start_time = float(state.get("start_time", time.time()) or time.time())
    elapsed = max(0.0, time.time() - start_time)
    remaining = max(0.0, total - elapsed)
    return {
        "total": total,
        "elapsed": elapsed,
        "remaining": remaining,
    }


def _budget_aware_timeout(
    state: PenetrationTesterState,
    configured_timeout: int,
    reserve_seconds: int = 45,
    min_timeout: int = 20,
) -> int:
    budget = _task_budget_snapshot(state)
    remaining = int(budget["remaining"])
    effective = min(int(configured_timeout), max(0, remaining - int(reserve_seconds)))
    return max(0, effective if effective > 0 else min_timeout)


def _adaptive_prompt_limits(state: PenetrationTesterState) -> Dict[str, int]:
    budget = _task_budget_snapshot(state)
    remaining = budget["remaining"]
    no_progress_rounds = int(state.get("no_progress_rounds", 0) or 0)
    tool_rounds = int(state.get("tool_rounds", 0) or 0)
    repeated_hypothesis_rounds = int(state.get("repeated_hypothesis_rounds", 0) or 0)

    limits = {
        "history": int(os.getenv("MAX_HISTORY_MESSAGES", "10")),
        "advisor_chars": int(os.getenv("ADVISOR_SUGGESTION_MAX_CHARS", "4000")),
        "skill_chars": int(os.getenv("SKILL_CONTEXT_MAX_CHARS", "12000")),
        "rag_chars": int(os.getenv("RAG_CONTEXT_MAX_CHARS", "4000")),
        "tool_message_chars": int(os.getenv("TOOL_MESSAGE_CONTEXT_MAX_CHARS", "2500")),
        "work_note_chars": int(os.getenv("WORKING_MEMORY_CONTEXT_MAX_CHARS", "3200")),
    }

    if remaining < 360 or no_progress_rounds >= 5 or tool_rounds >= 10 or repeated_hypothesis_rounds >= 4:
        limits["history"] = min(limits["history"], 8)
        limits["advisor_chars"] = min(limits["advisor_chars"], 2500)
        limits["skill_chars"] = min(limits["skill_chars"], 8000)
        limits["rag_chars"] = min(limits["rag_chars"], 2200)
        limits["tool_message_chars"] = min(limits["tool_message_chars"], 1800)
        limits["work_note_chars"] = min(limits["work_note_chars"], 2400)

    if remaining < 180 or no_progress_rounds >= 8 or repeated_hypothesis_rounds >= 6:
        limits["history"] = min(limits["history"], 6)
        limits["advisor_chars"] = min(limits["advisor_chars"], 1400)
        limits["skill_chars"] = min(limits["skill_chars"], 4500)
        limits["rag_chars"] = min(limits["rag_chars"], 1200)
        limits["tool_message_chars"] = min(limits["tool_message_chars"], 1200)
        limits["work_note_chars"] = min(limits["work_note_chars"], 1600)

    return limits


def _is_useful_path_hint(candidate: str) -> bool:
    ignored_paths = {
        "/fail",
        "/pass",
        "/failed",
        "/success",
        "/rejected",
        "/confirmed",
        "/status",
        "/result",
        "/error",
    }
    path = str(candidate or "").strip().lower()
    if not path or path in ignored_paths:
        return False
    if re.fullmatch(r"/[a-z]{2,12}", path):
        return False
    endpoint_markers = [
        ".action",
        ".jsp",
        ".php",
        ".do",
        ".cgi",
        "/api/",
        "/upload",
        "/login",
        "/admin",
        "/console",
        "/debug",
        "/graphql",
        "?",
    ]
    return any(marker in path for marker in endpoint_markers) or path.count("/") >= 2


def _normalize_surface_hint(candidate: str) -> str:
    text = str(candidate or "").strip()
    if not text:
        return ""
    text = text.rstrip(".,;:!?)>\"'")
    parsed = None
    if text.startswith("http://") or text.startswith("https://"):
        try:
            parsed = urlparse(text)
        except Exception:
            parsed = None
    elif text.startswith("/"):
        parsed = urlparse(text)

    if parsed:
        path = parsed.path or ""
        if not _is_useful_path_hint(path or text):
            return ""
        query_items = sorted(
            {
                part.split("=", 1)[0].strip().lower()
                for part in (parsed.query or "").split("&")
                if part.strip()
            }
        )
        query = f"?{'&'.join(query_items)}" if query_items else ""
        normalized = f"{path}{query}".lower()
        return normalized if _is_useful_path_hint(normalized) else ""

    if text.startswith("/") and _is_useful_path_hint(text):
        return text.lower()
    return ""


def _merge_unique_state_strings(existing: List[str], incoming: List[str], *, limit: int = 12) -> List[str]:
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


def _blocked_hypothesis_set(state: PenetrationTesterState) -> set[str]:
    return {
        str(item).strip().lower()
        for item in list(state.get("blocked_hypothesis_signatures") or [])
        if str(item).strip()
    }


def _blocked_hypothesis_families(state: PenetrationTesterState) -> set[str]:
    families = set()
    for item in _blocked_hypothesis_set(state):
        family = item.split(":", 1)[0].strip().lower()
        if family:
            families.add(family)
    return families


def _pick_candidate_surface_hint(state: PenetrationTesterState) -> str:
    message_hints = _extract_recon_surface_hints_from_messages(state, limit=12)
    candidates = _merge_unique_state_strings(
        [],
        list(state.get("candidate_surface_hints") or []) + list(message_hints or []),
        limit=12,
    )
    current_signature = str(state.get("last_hypothesis_signature") or "").strip().lower()
    current_path = ""
    if ":" in current_signature:
        current_path = current_signature.split(":", 1)[1].strip().lower()

    scored: List[tuple[int, str]] = []
    for raw in candidates:
        hint = _normalize_surface_hint(raw)
        if not hint:
            continue
        score = 0
        if "?" in hint:
            score += 4
        if any(marker in hint for marker in [".action", ".jsp", ".do", "/api/", "/upload", "/debug", "/console"]):
            score += 3
        if hint != current_path:
            score += 2
        if hint.count("/") >= 2:
            score += 1
        scored.append((score, hint))

    if not scored:
        target = _normalize_surface_hint(str(get_target_url(state) or "").strip())
        return target

    scored.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
    return scored[0][1]


def _build_surface_pivot_task(state: PenetrationTesterState) -> Optional[Dict]:
    surface_hint = _pick_candidate_surface_hint(state)
    if not surface_hint:
        return None

    last_hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip().lower()
    last_hypothesis_path = ""
    if ":" in last_hypothesis_signature:
        last_hypothesis_path = last_hypothesis_signature.split(":", 1)[1].strip().lower()
    no_progress_rounds = int(state.get("no_progress_rounds", 0) or 0)
    if last_hypothesis_path and surface_hint.lower() == last_hypothesis_path and no_progress_rounds >= 2:
        log_system_event(
            "[Planner] Skip duplicate surface pivot with no new evidence",
            {
                "surface": surface_hint,
                "last_hypothesis_signature": state.get("last_hypothesis_signature") or "",
                "no_progress_rounds": no_progress_rounds,
            },
            level=logging.WARNING,
        )
        return None

    last_signature = str(state.get("last_hypothesis_signature") or "").strip().lower()
    current_family = last_signature.split(":", 1)[0] if last_signature else ""
    if current_family and _should_preserve_family_specific_task(state, f"{current_family}:{surface_hint}"):
        target = get_execution_url(state) or get_target_url(state) or "target"
        action_path = surface_hint if surface_hint.startswith("/") else f"/{surface_hint}"
        canonical_action_path = action_path.split(";", 1)[0] or action_path
        family_vector_hints = {
            "struts2-ognl": "header-based expression or action/namespace path expression",
            "rce": "command execution path with deterministic runtime marker",
            "ssti": "template expression evaluation with deterministic output",
            "sqli": "boolean/time/error-based database behavior",
            "xss": "script payload reflection/execution context",
            "ssrf": "server-side outbound request to controlled indicator endpoint",
            "xxe": "external entity expansion or local file/entity leakage evidence",
            "file-upload": "upload-and-access or upload execution verification chain",
            "auth-bypass": "unauthenticated access to privileged resource/action",
            "file-inclusion": "controlled path traversal/local file inclusion signal",
        }
        vector_hint = family_vector_hints.get(current_family, "family-consistent deterministic verification vector")
        task_text = (
            f"Target: {target}\n"
            f"Hypothesis family: {current_family}\n"
            f"Primary action endpoint: {action_path}\n"
            "Run ONE focused family-bound verification task.\n"
            "Hard constraints:\n"
            f"1) Use the exact action endpoint above (and optional canonical fallback `{canonical_action_path}` only).\n"
            "2) Do NOT brute-force unrelated sibling endpoints in this round.\n"
            f"3) Use one primary vector aligned with this family: {vector_hint}.\n"
            "4) If primary vector is negative, optionally try one secondary vector and stop.\n"
            "5) Print request target, payload/vector, status code, and short response/header evidence.\n"
            "6) PASS only with deterministic, reproducible exploit evidence.\n"
            "7) FAIL if vectors do not produce deterministic evidence, and include explicit negative evidence.\n"
            "8) Output exactly one final VERDICT line (PASS or FAIL), do not emit contradictory interim verdicts.\n"
        )
        return {"agent": "poc", "task": task_text}

    blocked_families = sorted(_blocked_hypothesis_families(state))
    blocked_text = ", ".join(blocked_families[:4]) if blocked_families else "none"
    target = get_execution_url(state) or get_target_url(state) or "target"
    task_text = (
        f"Target: {target}\n"
        f"Candidate surface: {surface_hint}\n"
        "Run ONE surface-pivot verification task.\n"
        "Goal:\n"
        "- Determine whether this surface exposes a controllable input point, parameterized action, upload surface, debug/config endpoint, or other verifiable attack surface.\n"
        "Hard constraints:\n"
        "1) Focus on this exact surface only; do not switch to sibling guessed endpoints.\n"
        f"2) Use `{surface_hint}` as the primary endpoint/path in requests.\n"
        "3) Enumerate forms, parameters, linked actions, or controllable server-side behaviors for this surface.\n"
        "4) If and only if a deterministic verification check is justified, run one minimal PASS/FAIL check.\n"
        "5) If no controllable input or verification path exists, return FAIL with concrete evidence and stop.\n"
        f"6) Do NOT retry blocked hypothesis families in this round: {blocked_text}.\n"
    )
    return {"agent": "poc", "task": task_text}


def _collect_candidate_surface_hints(
    state: PenetrationTesterState,
    messages: List,
    findings: List[Dict],
) -> List[str]:
    hints: List[str] = []

    current_target = str(get_target_url(state) or "").strip()
    if current_target:
        normalized_target = _normalize_surface_hint(current_target)
        if normalized_target:
            hints.append(normalized_target)

    for finding in findings or []:
        if not (
            is_high_value_active_finding(finding)
            or has_strong_verification_signal(finding)
        ):
            continue
        for candidate in [
            finding.get("target_url"),
            finding.get("endpoint"),
            finding.get("target"),
            finding.get("matched_url"),
        ]:
            normalized = _normalize_surface_hint(str(candidate or "").strip())
            if normalized:
                hints.append(normalized)

    pending_task = dict(state.get("pending_task") or {})
    pending_task_text = str(pending_task.get("task") or "")
    if pending_task_text:
        path_hint = _extract_task_path_hint(pending_task_text)
        if path_hint:
            normalized = _normalize_surface_hint(path_hint)
            if normalized:
                hints.append(normalized)

    for msg in list(messages or [])[-6:]:
        content = str(getattr(msg, "content", "") or "")
        if not content.strip():
            continue
        lower = content.lower()
        has_surface_signal = any(
            token in lower
            for token in [
                "forms found",
                "input fields",
                "upload indicators",
                "form detected",
                "surface enumeration complete",
                "controllable input",
                "parameterized behavior",
                "candidate surface:",
                "action=\"/",
                "action: /",
                "form action",
                "endpoint:",
                "route:",
            ]
        )
        if not has_surface_signal:
            continue
        for url in re.findall(r"https?://[^\s'\"`<>]+", content, flags=re.IGNORECASE):
            normalized = _normalize_surface_hint(url)
            if normalized:
                hints.append(normalized)
        for action in re.findall(r"action\s*[:=]\s*`?([/\w.\-;?=&%]+)`?", content, flags=re.IGNORECASE):
            normalized = _normalize_surface_hint(action)
            if normalized:
                hints.append(normalized)
        for path in re.findall(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+)", content):
            normalized = _normalize_surface_hint(path)
            if normalized:
                hints.append(normalized)

    return _merge_unique_state_strings([], hints, limit=12)


def _extract_task_path_hint(task_text: str) -> str:
    if not task_text:
        return ""

    url_match = re.search(r"https?://[^\s'\"`]+", task_text, re.IGNORECASE)
    if url_match:
        parsed = urlparse(url_match.group(0))
        if parsed.path and _is_useful_path_hint(parsed.path):
            return parsed.path.lower()

    path_match = re.search(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)", task_text)
    if path_match and _is_useful_path_hint(path_match.group(1)):
        return path_match.group(1).lower()
    return ""


def _tool_output_has_explicit_verdict(content: str) -> bool:
    lower = normalize_text_content(content).lower()
    verdict_markers = [
        "[conclusion]",
        "[verification result]",
        "verification result",
        "verification verdict",
        "pass",
        "fail",
        "not vulnerable",
        "blocked",
        "no runtime output",
        "rejected",
        "confirmed",
        "结论",
        "验证结果",
        "未检测到",
        "未发现",
    ]
    return any(marker in lower for marker in verdict_markers)


def _compress_tool_output_for_decision(content: str, preview_chars: int = 1200) -> str:
    normalized = normalize_text_content(content)
    if not normalized:
        return normalized

    keep_markers = [
        "target",
        "url",
        "payload",
        "status",
        "evidence",
        "result",
        "verdict",
        "pass",
        "fail",
        "not vulnerable",
        "blocked",
        "runtime",
        "whoami",
        "uid=",
        "gid=",
        "exit code",
        "结论",
        "验证",
        "证据",
        "失败",
        "未检测到",
        "未发现",
    ]
    kept_lines: List[str] = []
    seen = set()
    for line in normalized.split("\n"):
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if any(marker in lower for marker in keep_markers):
            key = lower[:240]
            if key not in seen:
                kept_lines.append(line)
                seen.add(key)
        if len(kept_lines) >= 28:
            break

    if not kept_lines:
        kept_lines.append(_truncate_text_for_prompt(normalized, preview_chars))

    decision_view = "\n".join(kept_lines)
    preview = _truncate_text_for_prompt(normalized, preview_chars)
    if decision_view == preview:
        return decision_view
    return f"[TOOL_OUTPUT_DECISION_VIEW]\n{decision_view}\n\n[TOOL_OUTPUT_PREVIEW]\n{preview}"


def _parse_hypothesis_block(text: str) -> Dict[str, object]:
    content = str(text or "")
    match = re.search(r"\[HYPOTHESIS\](.*?)\[/HYPOTHESIS\]", content, re.IGNORECASE | re.DOTALL)
    if not match:
        return {}
    block = match.group(1)

    def _pick(key: str) -> str:
        m = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", block)
        return m.group(1).strip() if m else ""

    vuln_type = _pick("vuln_type").strip().lower()
    product_family = _pick("product_family").strip().lower()
    raw_candidates = _pick("cve_candidates")
    cve_candidates = [x.upper() for x in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", raw_candidates, re.IGNORECASE)]
    confidence_text = _pick("confidence")
    try:
        confidence = float(confidence_text)
    except Exception:
        confidence = 0.0
    vector = _pick("vector")
    return {
        "vuln_type": vuln_type or "unknown",
        "product_family": product_family or "unknown",
        "cve_candidates": cve_candidates,
        "confidence": max(0.0, min(1.0, confidence)),
        "vector": vector,
    }


def _hypothesis_to_history_line(role: str, hypothesis: Dict[str, object]) -> Optional[str]:
    if not isinstance(hypothesis, dict) or not hypothesis:
        return None
    confidence = float(hypothesis.get("confidence") or 0.0)
    min_conf = float(os.getenv("HYPOTHESIS_HINT_MIN_CONFIDENCE", "0.55"))
    if confidence < min_conf:
        return None
    vuln_type = str(hypothesis.get("vuln_type") or "unknown").strip().lower()
    product_family = str(hypothesis.get("product_family") or "unknown").strip().lower()
    cves = ", ".join(list(hypothesis.get("cve_candidates") or [])[:4]) or "N/A"
    vector = _truncate_text_for_prompt(str(hypothesis.get("vector") or "N/A"), 120)
    return (
        f"[Hypothesis/{role}] vuln_type={vuln_type} | family={product_family} | "
        f"cves={cves} | confidence={confidence:.2f} | vector={vector}"
    )


def _infer_task_hypothesis_signature(task: Dict) -> str:
    if not isinstance(task, dict):
        return ""

    task_text = str(task.get("task") or "").strip().lower()
    if not task_text:
        return ""

    categories = [
        ("struts2-ognl", ["struts2", "ognl", "xwork", "s2-0", "doupload.action", "webconsole", "debug=command"]),
        ("ssti", ["ssti", "template injection", "jinja", "freemarker", "twig", "velocity", "{{", "${7*7}"]),
        ("sqli", ["sql injection", "sqli", "union select", "sleep(", "benchmark(", "order by"]),
        ("xss", ["xss", "cross-site scripting", "<script", "onerror=", "svg/onload"]),
        ("ssrf", ["ssrf", "server-side request forgery", "metadata", "169.254.169.254", "gopher://"]),
        ("xxe", ["xxe", "xml external entity", "<!doctype", "<!entity"]),
        ("file-upload", ["upload", "multipart/form-data", ".jsp", ".php", "filename=", "put "]),
        ("file-inclusion", ["lfi", "rfi", "file inclusion", "../", "..\\", "/etc/passwd"]),
        ("auth-bypass", ["auth bypass", "authentication bypass", "jwt", "login", "session", "token"]),
        ("bruteforce", ["hydra", "brute force", "password spray", "weak password"]),
        ("recon", ["nmap", "whatweb", "nikto", "gobuster", "dirb", "ffuf", "fingerprint", "enumerate"]),
        ("rce", ["rce", "remote code execution", "command execution", "whoami", "uid=", "cmd.exe", "/bin/sh"]),
    ]
    family = ""
    for name, markers in categories:
        if any(marker in task_text for marker in markers):
            family = name
            break

    if not family:
        return ""

    path_hint = _extract_task_path_hint(task_text)
    if path_hint:
        return f"{family}:{path_hint}"
    return family


def _should_force_review(state: PenetrationTesterState) -> bool:
    findings = state.get("findings") or []
    has_valuable_findings = has_actionable_active_findings(findings)

    base_no_progress = int(os.getenv("FORCE_REVIEW_NO_PROGRESS_ROUNDS", "3"))
    base_repeat_hypothesis = int(os.getenv("FORCE_REVIEW_REPEAT_HYPOTHESIS_ROUNDS", "4"))
    base_repeat_task = int(os.getenv("FORCE_REVIEW_REPEAT_TASK_ROUNDS", "3"))

    if has_valuable_findings:
        base_no_progress += 2
        base_repeat_hypothesis += 2
        base_repeat_task += 1

    return bool(
        int(state.get("no_progress_rounds", 0) or 0) >= base_no_progress
        or int(state.get("repeated_hypothesis_rounds", 0) or 0) >= base_repeat_hypothesis
        or int(state.get("repeated_task_rounds", 0) or 0) >= base_repeat_task
    )


def _strategy_switch_guidance(state: PenetrationTesterState) -> str:
    repeated_hypothesis_rounds = int(state.get("repeated_hypothesis_rounds", 0) or 0)
    no_progress_rounds = int(state.get("no_progress_rounds", 0) or 0)
    hypothesis_signature = str(state.get("last_hypothesis_signature") or "current hypothesis").strip()

    if repeated_hypothesis_rounds >= 4:
        return (
            "Current route appears stuck on the same hypothesis family.\n"
            f"- Stuck family: {hypothesis_signature}\n"
            "- Switch strategy instead of repeating the same exploit wording.\n"
            "- Valid pivots: fingerprint/version discrimination, endpoint/parameter discovery, proof-only verification, or explicit rejection of the current family.\n"
            "- The next action must be one falsifiable experiment with PASS/FAIL criteria."
        )
    if no_progress_rounds >= 3:
        return (
            "Current route shows repeated no-progress execution.\n"
            "- Do not continue brute-force retries of the same idea.\n"
            "- Switch to a different evidence-gathering strategy: targeted recon, exploit precondition check, or a deterministic runtime marker.\n"
            "- The next action must be a single falsifiable experiment."
        )
    return ""


def _has_recent_partial_verification_signal(state: PenetrationTesterState) -> bool:
    for item in list(state.get("action_history") or [])[-8:]:
        text = str(item).strip().lower()
        if not text:
            continue
        if text.startswith("[observation/") and any(
            token in text
            for token in [
                "partial",
                "transport",
                "incomplete",
                "processing detected",
                "未完成验证",
            ]
        ):
            return True
        if text.startswith("[failure/") and any(
            token in text
            for token in [
                "传输层",
                "transport",
                "incomplete",
                "未完成验证",
            ]
        ):
            return True
    return False


def _build_execution_outcome(
    *,
    state: PenetrationTesterState,
    result: Dict,
    smart_details: List[Dict],
    is_failure: bool,
    connectivity_hits: int,
    progress_from_output: bool,
) -> Dict:
    findings = [f for f in list(result.get("findings") or []) if isinstance(f, dict)]
    confirmed = [f for f in findings if (f.get("status") or "").lower() == "confirmed"]
    suspected = [f for f in findings if (f.get("status") or "").lower() == "suspected"]
    rejected = [f for f in findings if (f.get("status") or "").lower() == "rejected"]
    actionable_counts = count_actionable_findings(findings)
    actionable_confirmed = actionable_counts.get("confirmed", 0)
    actionable_suspected = actionable_counts.get("suspected", 0)

    detail_text = "\n".join(
        [
            str(item.get("reason") or "")
            + "\n"
            + str(item.get("key_info_preview") or "")
            for item in (smart_details or [])
            if isinstance(item, dict)
        ]
    ).lower()
    has_partial_signal = any(
        token in detail_text
        for token in [
            "partial",
            "processing detected",
            "transport",
            "incomplete",
            "未完成验证",
            "部分处理",
            "弱处理迹象",
        ]
    ) or any(
        str(f.get("evidence_quality") or "").strip().lower() == "partial_with_transport_error"
        for f in findings
    )
    has_surface_only_signal = any(
        token in detail_text
        for token in [
            "surface",
            "input point",
            "parameterized behavior",
            "multipart post",
            "可交互",
            "输入点",
            "验证链尚未成立",
        ]
    )

    if result.get("flag"):
        tool_status = "success"
        verification_status = "confirmed"
        progress_status = "strong"
        summary = "Tool execution produced a verified success artifact."
    elif actionable_confirmed > 0:
        tool_status = "success"
        verification_status = "confirmed"
        progress_status = "strong"
        summary = "Structured findings reached confirmed status."
    elif actionable_suspected > 0:
        tool_status = "partial"
        verification_status = "suspected"
        progress_status = "strong"
        summary = "Structured findings were retained as suspected and should guide the next step."
    elif has_partial_signal or has_surface_only_signal:
        tool_status = "partial"
        verification_status = "inconclusive"
        progress_status = "weak"
        if has_surface_only_signal:
            summary = "Execution only confirmed a reachable or controllable surface; the vulnerability verification chain is still incomplete."
        else:
            summary = "Execution exposed partial verification signals but did not finish a deterministic confirmation chain."
    elif connectivity_hits > 0 and is_failure:
        tool_status = "transport_error"
        verification_status = "inconclusive"
        progress_status = "none"
        summary = "Execution was interrupted by connectivity or transport errors."
    elif rejected or is_failure:
        tool_status = "failure"
        verification_status = "rejected" if rejected else "inconclusive"
        progress_status = "none"
        summary = "Execution ended with negative evidence or an explicit failure verdict."
    elif progress_from_output:
        tool_status = "partial"
        verification_status = "inconclusive"
        progress_status = "weak"
        summary = "Execution output contained weak progress signals but no structured finding."
    else:
        tool_status = "inconclusive"
        verification_status = "inconclusive"
        progress_status = "none"
        summary = "Execution did not produce actionable verification evidence."

    should_retry_same_hypothesis = (
        tool_status in {"partial", "transport_error"}
        and verification_status != "confirmed"
        and (
            has_partial_signal
            or connectivity_hits > 0
            or actionable_suspected > 0
        )
    )

    return {
        "tool_status": tool_status,
        "verification_status": verification_status,
        "progress_status": progress_status,
        "summary": summary,
        "findings_added": len(findings),
        "confirmed_count": actionable_confirmed,
        "suspected_count": actionable_suspected,
        "rejected_count": len(rejected),
        "connectivity_issue": connectivity_hits > 0,
        "should_retry_same_hypothesis": should_retry_same_hypothesis,
        "execution_attempts": int(state.get("execution_attempts", 0) or 0) + 1,
    }


def _enforce_falsifiable_dispatch_task(task: Dict, state: PenetrationTesterState) -> Dict:
    if not isinstance(task, dict):
        return task

    task_text = str(task.get("task") or "").strip()
    if not task_text:
        return task

    lower = task_text.lower()
    needs_footer = not all(marker in lower for marker in ["pass", "fail"])
    if _should_force_review(state):
        needs_footer = True

    if not needs_footer:
        return task

    footer = (
        "\n\nFalsifiable experiment requirements:\n"
        "1) State exactly one hypothesis.\n"
        "2) Use one deterministic check or runtime marker.\n"
        "3) Output explicit PASS and FAIL criteria.\n"
        "4) If FAIL, stop and summarize why this hypothesis should be downgraded or rejected.\n"
        "5) Do not append broad scan tasks to this round.\n"
    )
    updated = dict(task)
    updated["task"] = task_text + footer
    return updated


def _summarize_new_findings_for_history(findings: List[Dict]) -> List[str]:
    items: List[str] = []
    for finding in findings[:5]:
        status = str(finding.get("status") or "unknown").lower()
        vuln_type = str(finding.get("vuln_type") or "unknown")
        cve = str(finding.get("cve") or "").strip().upper()
        target = str(
            finding.get("target_url")
            or finding.get("endpoint")
            or finding.get("target")
            or "N/A"
        ).strip()
        evidence = str(finding.get("evidence") or "").strip().replace("\n", " ")
        evidence = _truncate_text_for_prompt(evidence, 140)
        line = f"[Finding/{status}] {vuln_type}"
        if cve:
            line += f" {cve}"
        line += f" @ {target}"
        if evidence:
            line += f" | {evidence}"
        items.append(line)
    return items


def _has_strong_runtime_confirmation(finding: Dict) -> bool:
    if bool(finding.get("strict_verified")):
        return True

    strict_mode = os.getenv("STRICT_VERIFICATION", "false").strip().lower() == "true"

    text = "\n".join(
        [
            str(finding.get("evidence") or ""),
            "\n".join(str(x) for x in (finding.get("request_evidence") or []) if x),
            "\n".join(str(x) for x in (finding.get("response_evidence") or []) if x),
        ]
    ).lower()
    positive_markers = [
        "uid=",
        "gid=",
        "whoami",
        "root:x:",
        "daemon:x:",
        "x-cmd-result:",
        "x-check:",
        "x-ognl-test:",
        "x-user-name:",
        "x-test-bypass:",
        "x-struts2-test:",
        "command execution successful",
        "execution result",
        "shell output",
        "vulnerable: true",
        '"vulnerable": true',
        "exploit success",
        "[status] vulnerable",
        "pass - vulnerability confirmed",
        "successfully injected in response",
        "[result] pass",
        "result: pass",
        "verification: pass",
        "confirmed vulnerable",
        "vulnerability exists",
        "rce confirmed",
        "injection successful",
        "payload executed",
        "ognl injection works",
        "response header injection successful",
        "漏洞存在",
        "确认漏洞",
        "验证成功",
        "命令执行成功",
        "注入成功",
    ]
    negative_markers = [
        "not vulnerable",
        "execution failed",
        "response does not contain",
        "payload not executed",
        "failed or blocked",
        "without command output",
        "result: fail",
        "[result] fail",
        "verification: fail",
    ]
    has_header_artifact = bool(re.search(r"\bx-[a-z0-9_-]+:\s*[a-z0-9._:-]{3,}\b", text))
    has_positive = any(m in text for m in positive_markers) or has_header_artifact
    has_negative = any(m in text for m in negative_markers)
    if not strict_mode:
        return has_positive and not has_negative
    return has_positive and not has_negative


def _verification_gap_summary(finding: Dict) -> str:
    checks = dict(finding.get("verification_checks") or {})
    if not checks:
        return ""
    missing = [name for name, ok in checks.items() if not bool(ok)]
    if not missing:
        return "verification_checks_complete"
    return "missing:" + ",".join(missing[:6])


def _apply_evidence_grading(findings: List[Dict]) -> List[Dict]:
    enable_auto_downgrade = os.getenv("ENABLE_AUTO_DOWNGRADE", "true").strip().lower() == "true"
    high_confidence_threshold = float(os.getenv("HIGH_CONFIDENCE_THRESHOLD", "0.75"))
    graded: List[Dict] = []
    for finding in findings or []:
        item = dict(finding)
        status = str(item.get("status") or "").lower()
        if status == "confirmed":
            has_strong_evidence = _has_strong_runtime_confirmation(item)
            confidence = float(item.get("confidence") or item.get("score") or item.get("existence_rate") or 0.0)
            should_downgrade = (
                enable_auto_downgrade
                and not has_strong_evidence
                and confidence < high_confidence_threshold
            )
            if should_downgrade:
                item["status"] = "suspected"
                item["audit_note"] = "downgraded_to_suspected_due_to_insufficient_runtime_evidence"
                gap_summary = _verification_gap_summary(item)
                if gap_summary:
                    notes = list(item.get("uncertainty_notes") or [])
                    notes.append(f"Evidence grading gap: {gap_summary}")
                    item["uncertainty_notes"] = notes
            elif not has_strong_evidence and confidence >= high_confidence_threshold:
                item["audit_note"] = "kept_confirmed_due_to_high_confidence"
        graded.append(item)
    return graded


def _sanitize_history_for_tool_call_chain(history: List, max_history: int, max_tool_content_chars: Optional[int] = None) -> List:
    """
    Keep recent history while ensuring ToolMessage has a matching prior AI tool_call.
    This prevents provider-side 400 errors caused by orphan tool messages.
    """
    if len(history) > max_history:
        history = history[-max_history:]

    sanitized: List = []
    open_tool_call_ids = set()

    if max_tool_content_chars is None:
        max_tool_content_chars = int(os.getenv("TOOL_MESSAGE_CONTEXT_MAX_CHARS", "2500"))

    for msg in history:
        if isinstance(msg, AIMessage):
            tool_calls = getattr(msg, "tool_calls", None) or []
            for tc in tool_calls:
                tc_id = tc.get("id")
                if tc_id:
                    open_tool_call_ids.add(tc_id)
            sanitized.append(msg)
            continue

        if isinstance(msg, ToolMessage):
            tool_call_id = getattr(msg, "tool_call_id", None)
            if tool_call_id and tool_call_id in open_tool_call_ids:
                open_tool_call_ids.discard(tool_call_id)
                content = getattr(msg, "content", "")
                if isinstance(content, str) and len(content) > max_tool_content_chars:
                    content = _truncate_text_for_prompt(content, max_tool_content_chars)
                    trimmed_msg = ToolMessage(
                        content=content,
                        tool_call_id=tool_call_id,
                        name=getattr(msg, "name", None),
                    )
                    sanitized.append(trimmed_msg)
                else:
                    sanitized.append(msg)
            continue

        sanitized.append(msg)

    return sanitized


def _extract_advisor_sections_for_planner(text: str) -> str:
    normalized = normalize_text_content(text)
    if not normalized.strip():
        return ""

    kept: List[str] = []
    current_section = ""
    section_aliases = {
        "progress": ("## progress summary", "## 进度总结", "## 进度分析", "## progress analysis"),
        "hypotheses": ("## current hypotheses", "## 当前假设"),
        "recommendation": ("## next recommendation", "## 下一步建议"),
        "review": ("## review notes", "## 审稿备注", "## review"),
    }

    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        matched = ""
        for section, aliases in section_aliases.items():
            if any(lower.startswith(alias) for alias in aliases):
                matched = section
                break
        if matched:
            current_section = matched
            title_map = {
                "progress": "## Progress Summary",
                "hypotheses": "## Current Hypotheses",
                "recommendation": "## Next Recommendation",
                "review": "## Review Notes",
            }
            title = title_map[matched]
            if not kept or kept[-1] != title:
                kept.append(title)
            continue

        if current_section in {"hypotheses", "recommendation", "review"}:
            kept.append(line)
        elif current_section == "progress":
            if (
                "strongest evidence" in lower
                or "最强证据" in line
                or "关键证据" in line
                or "strongest signal" in lower
            ):
                kept.append(line)

    return "\n".join(kept).strip()


def _sanitize_advisor_suggestion_for_planner(state: PenetrationTesterState, text: str) -> str:
    normalized = normalize_text_content(text)
    if not normalized.strip():
        return ""

    tool_rounds = int(state.get("tool_rounds", 0) or 0)
    extracted = _extract_advisor_sections_for_planner(normalized)
    if not extracted:
        extracted = _truncate_text_for_prompt(normalized, 1600)

    lines: List[str] = []
    if tool_rounds == 0:
        lines.extend(
            [
                "## Progress Summary",
                "- No executed verification yet; only automated reconnaissance and planning review are available.",
            ]
        )
        stripped_lines = []
        for line in extracted.splitlines():
            lower = line.lower().strip()
            if (
                "attempted path" in lower
                or "rejected path" in lower
                or "已尝试" in line
                or "尝试路径" in line
                or "通过 `/doupload.action`" in line.lower()
                or "through /doupload.action" in lower
                or "content-type" in lower and ("attempted" in lower or "已尝试" in line)
            ):
                continue
            stripped_lines.append(line)
        extracted = "\n".join(stripped_lines).strip()
        if extracted.lower().startswith("## progress summary"):
            extracted = extracted.split("\n", 1)[1].strip() if "\n" in extracted else ""

    findings = list(state.get("findings") or [])
    last_execution_outcome = dict(state.get("last_execution_outcome") or {})
    has_stable_positive_evidence = any(
        isinstance(item, dict)
        and (
            has_strong_verification_signal(item)
            or is_high_value_active_finding(item)
        )
        for item in findings
    ) or (
        str(last_execution_outcome.get("verification_status") or "").strip().lower() == "confirmed"
        and str(last_execution_outcome.get("tool_status") or "").strip().lower() == "success"
    )

    if extracted:
        filtered_lines: List[str] = []
        latest_outcome = dict(state.get("last_execution_outcome") or {})
        latest_summary = str(latest_outcome.get("summary") or "").strip().lower()
        latest_tool_status = str(latest_outcome.get("tool_status") or "").strip().lower()
        latest_verification_status = str(latest_outcome.get("verification_status") or "").strip().lower()
        latest_is_surface_only = (
            latest_verification_status == "inconclusive"
            and latest_tool_status in {"partial", "failure", "inconclusive"}
            and "surface" in latest_summary
        )
        for line in extracted.splitlines():
            lower = line.lower().strip()
            if (
                not has_stable_positive_evidence
                and (
                    "strongest evidence" in lower
                    or "最强证据" in line
                    or "关键证据" in line
                    or "pass: ognl injection successful" in lower
                    or "vulnerability confirmed" in lower
                    or "response header injection successful" in lower
                    or "ognl injection successful" in lower
                )
            ):
                continue
            if (
                "host.docker.internal" in lower
                and (
                    "wrong host" in lower
                    or "主机名错误" in line
                    or "而非" in line
                    or "rather than" in lower
                    or "instead of" in lower
                )
            ):
                continue
            if latest_is_surface_only and (
                "strongest evidence" in lower
                or "最强证据" in line
                or "attempted path" in lower
                or "已尝试路径" in line
                or "rejected path" in lower
                or "content-type" in lower
                or "struts2-ognl" in lower
            ):
                continue
            filtered_lines.append(line)
        extracted = "\n".join(filtered_lines).strip()

    latest_outcome = dict(state.get("last_execution_outcome") or {})
    latest_summary = str(latest_outcome.get("summary") or "").strip()
    latest_is_surface_only = (
        str(latest_outcome.get("verification_status") or "").strip().lower() == "inconclusive"
        and str(latest_outcome.get("tool_status") or "").strip().lower() in {"partial", "failure", "inconclusive"}
        and "surface" in latest_summary.lower()
    )
    if latest_is_surface_only:
        lines.extend(
            [
                "## Progress Summary",
                "- Latest result only confirms a reachable or controllable surface; it does not verify a vulnerability.",
                "- Treat the current family as a candidate path only until deterministic runtime evidence appears.",
            ]
        )

    if extracted:
        lines.append(extracted)
    sanitized = "\n".join(lines).strip()
    return _truncate_text_for_prompt(sanitized, int(os.getenv("ADVISOR_SUGGESTION_STATE_MAX_CHARS", "1800")))


def _skill_context_signature(
    *,
    skill_stage: str,
    explicit_skills: List[str],
    hint_and_context: str,
    recon_context: str,
    recent_tool_context: str,
) -> str:
    basis = "\n".join(
        [
            skill_stage,
            ",".join(explicit_skills),
            _truncate_text_for_prompt(hint_and_context, 800),
            _truncate_text_for_prompt(recon_context, 1200),
            _truncate_text_for_prompt(recent_tool_context, 1200),
        ]
    )
    return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()


def _compact_main_recovery_prompt(state: PenetrationTesterState) -> str:
    current_context = build_main_context(state, compact=True, include_action_history=False)
    return (
        MAIN_AGENT_PLANNER_PROMPT.format(current_context=current_context)
        + "\n\n## Compact Recovery Mode\n"
        + "The previous planning attempt failed because the model call was too slow or the provider was overloaded.\n"
        + "You must be concise.\n"
        + "Output exactly one of:\n"
        + "1) one minimal [DISPATCH_TASK], or\n"
        + "2) [REQUEST_ADVISOR_HELP].\n"
        + "If there have been zero executed tool rounds but automated reconnaissance already identified a concrete form/endpoint, prefer one minimal falsifiable dispatch instead of another advisor-only loop.\n"
        + "Do not restate long summaries.\n"
    )


async def build_multi_agent_graph(config: RunnableConfig):
    """
    构建多 Agent 协作图。

    Args:
        config: LangGraph 运行配置

    Returns:
        编译后的 LangGraph 应用
    """
    # 初始化 LLM
    from shell_agent.model import create_advisor_model, create_model
    from shell_agent.core.singleton import get_config_manager

    agent_config = get_config_manager().config

    # 主模型
    main_llm = create_model(agent_config)
    log_system_event("[Graph V2] Initialized main_llm")

    # 顾问模型
    advisor_llm = create_advisor_model(agent_config)
    log_system_event("[Graph V2] Initialized advisor_llm")

    # 从 config 中读取 manual_mode
    manual_mode = False
    if config and hasattr(config, "get"):
        configurable = config.get("configurable", {})
        manual_mode = configurable.get("manual_mode", False)

    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode)


async def _build_graph_internal(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    构建三层协作图的内部实现。

    Args:
        main_llm: 主模型
        advisor_llm: 顾问模型
        manual_mode: 是否手动模式
        graph_name: 图名称（用于 Langfuse trace name）
    """
    # ==================== 1. 初始化记忆和工具 ====================
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools(manual_mode=manual_mode)
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools

    # 分离工具：PoC 使用 execute_python_poc，Docker 使用 execute_command
    poc_tool = next((t for t in pentest_tools if t.name == "execute_python_poc"), None)
    docker_tool = next((t for t in pentest_tools if t.name == "execute_command"), None)
    submit_tool = next((t for t in memory_tools if t.name == "submit_flag"), None)

    log_system_event(
        "[Graph V2] Initialized three-layer architecture",
        {
            "poc_tool": poc_tool.name if poc_tool else None,
            "docker_tool": docker_tool.name if docker_tool else None,
            "submit_tool": submit_tool.name if submit_tool else None,
            "manual_mode": manual_mode
        }
    )

    # 执行层 Agent 绑定各自工具
    poc_llm_with_tools = main_llm.bind_tools([poc_tool]) if poc_tool else None
    docker_llm_with_tools = main_llm.bind_tools([docker_tool]) if docker_tool else None

    # ToolNode 用于统一执行工具
    base_tool_node = ToolNode(all_tools)

    async def _summarize_tool_output_if_needed(tool_name: str, content: str) -> str:
        """
        在工具输出过长时，使用 LLM 生成摘要，缓解上下文超长问题。
        """
        if not isinstance(content, str):
            content = str(content)
        content = normalize_text_content(content)
        if not content.strip():
            return content
        if _looks_like_local_scaffolding_output(tool_name, content):
            return "[LOCAL_COMMAND]\nLocal shell command completed in the executor container. No target-side evidence was produced."

        enable_summary = os.getenv("ENABLE_TOOL_SUMMARY", "true").strip().lower() == "true"
        threshold = int(os.getenv("TOOL_SUMMARY_THRESHOLD", "5000"))
        if not enable_summary or len(content) <= max(1, threshold):
            return content

        summary_timeout_sec = int(os.getenv("TOOL_SUMMARY_TIMEOUT_SEC", "60"))
        preview_chars = int(os.getenv("TOOL_SUMMARY_PREVIEW_CHARS", "1200"))
        summary_input = _truncate_text_for_prompt(content, int(os.getenv("TOOL_SUMMARY_INPUT_MAX_CHARS", "12000")))

        if _tool_output_has_explicit_verdict(content):
            return _compress_tool_output_for_decision(content, preview_chars=preview_chars)

        try:
            async with asyncio.timeout(summary_timeout_sec):
                response = await retry_llm_call(
                    main_llm.ainvoke,
                    [
                        SystemMessage(content=TOOL_OUTPUT_SUMMARY_PROMPT),
                        HumanMessage(content=f"工具: {tool_name}\n\n原始输出:\n{summary_input}"),
                    ],
                    limiter=main_limiter,
                    max_retries=2,
                )
            summary = (getattr(response, "content", "") or "").strip()
            if not summary:
                return content
            return (
                f"[TOOL_OUTPUT_SUMMARY]\n{summary}\n\n"
                f"[TOOL_OUTPUT_PREVIEW]\n{_truncate_text_for_prompt(content, preview_chars)}"
            )
        except Exception as exc:
            log_system_event(
                "[Tool Summary] 摘要失败，回退原始输出",
                {"tool": tool_name, "error": str(exc)},
                level=logging.WARNING,
            )
            return content

    async def _attempt_compact_main_recovery(
        state: PenetrationTesterState,
        *,
        reason: str,
    ) -> Optional[Dict]:
        budget = _task_budget_snapshot(state)
        if budget["remaining"] <= int(os.getenv("MAIN_AGENT_COMPACT_MIN_BUDGET_SEC", "90")):
            return None

        prompt = _compact_main_recovery_prompt(state)
        advisor_suggestion = _sanitize_advisor_suggestion_for_planner(state, str(state.get("advisor_suggestion") or ""))
        if advisor_suggestion:
            prompt += (
                "\n\n## Advisor Guidance (sanitized)\n"
                + _truncate_text_for_prompt(advisor_suggestion, 900)
            )
        prompt += f"\n\n## Recovery Trigger\n- {reason}"

        messages = [SystemMessage(content=prompt)]
        compact_timeout = min(
            int(os.getenv("MAIN_AGENT_COMPACT_TIMEOUT_SEC", "35")),
            _budget_aware_timeout(
                state,
                configured_timeout=int(os.getenv("MAIN_AGENT_COMPACT_TIMEOUT_SEC", "35")),
                reserve_seconds=int(os.getenv("MAIN_AGENT_BUDGET_RESERVE_SEC", "60")),
                min_timeout=int(os.getenv("MAIN_AGENT_MIN_TIMEOUT_SEC", "20")),
            ),
        )
        if compact_timeout <= 0:
            return None

        try:
            async with asyncio.timeout(compact_timeout):
                ai_message: AIMessage = await retry_llm_call(
                    main_llm.ainvoke,
                    messages,
                    max_retries=1,
                    base_delay=1.0,
                    limiter=main_limiter,
                )
        except Exception as exc:
            log_system_event(
                "[Main Agent] Compact recovery planning failed",
                {"reason": reason, "error": str(exc)},
                level=logging.WARNING,
            )
            return None

        ai_message = _normalize_ai_message_content(ai_message)
        content = str(ai_message.content or "")
        dispatch_task = _parse_dispatch_task(content)
        request_help = "[REQUEST_ADVISOR_HELP]" in content
        if not dispatch_task and not request_help:
            return None

        result: Dict[str, object] = {
            "messages": [ai_message],
            "advisor_suggestion": "",
            "request_advisor_help": request_help and not dispatch_task,
            "main_rounds": 1,
            "no_action_rounds": 0 if dispatch_task else (int(state.get("no_action_rounds", 0) or 0) + 1),
            "advisor_loop_rounds": 0 if dispatch_task else (int(state.get("advisor_loop_rounds", 0) or 0) + 1),
        }
        if dispatch_task:
            dispatch_task = _normalize_dispatch_task_target(dispatch_task, state)
            dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
            dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
            compact_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
            if (
                not has_actionable_active_findings(state.get("findings") or [])
                and _infer_skill_stage(state, "") != "vuln"
                and _is_family_specific_hypothesis_signature(compact_hypothesis_signature)
                and not _should_preserve_family_specific_task(state, compact_hypothesis_signature)
            ):
                replacement_task = _build_surface_pivot_task(state) or {
                    "agent": "poc",
                    "task": _focused_verification_task(state),
                }
                dispatch_task = _normalize_dispatch_task_target(replacement_task, state)
                dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
                dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
                compact_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
                result["action_history"] = [
                    f"[Planner] compact_recovery_stage_guard | phase={_infer_skill_stage(state, '')} | hypothesis={compact_hypothesis_signature or 'generic'}"
                ]
            if compact_hypothesis_signature and compact_hypothesis_signature.lower() in _blocked_hypothesis_set(state):
                pivot_task = _build_surface_pivot_task(state)
                if pivot_task:
                    pivot_task = _normalize_dispatch_task_target(pivot_task, state)
                    pivot_task = _stabilize_dispatch_task(pivot_task, state)
                    pivot_task = _enforce_falsifiable_dispatch_task(pivot_task, state)
                    pivot_signature = _task_signature(pivot_task)
                    if pivot_signature and pivot_signature == str(state.get("last_task_signature") or ""):
                        result["request_advisor_help"] = True
                        result["no_action_rounds"] = int(state.get("no_action_rounds", 0) or 0) + 1
                        result["advisor_loop_rounds"] = int(state.get("advisor_loop_rounds", 0) or 0) + 1
                        result["action_history"] = [
                            f"[Planner] compact_recovery_duplicate_pivot | blocked={compact_hypothesis_signature} | surface={_pick_candidate_surface_hint(state) or 'N/A'}"
                        ]
                    else:
                        result["pending_task"] = pivot_task
                        result["request_advisor_help"] = False
                        result["action_history"] = [
                            f"[Planner] compact_recovery_pivot_surface | blocked={compact_hypothesis_signature} | surface={_pick_candidate_surface_hint(state) or 'N/A'}"
                        ]
                else:
                    result["request_advisor_help"] = True
                    result["no_action_rounds"] = int(state.get("no_action_rounds", 0) or 0) + 1
                    result["advisor_loop_rounds"] = int(state.get("advisor_loop_rounds", 0) or 0) + 1
                    result["action_history"] = [
                        f"[Planner] compact_recovery_blocked_hypothesis | hypothesis={compact_hypothesis_signature}"
                    ]
            else:
                result["pending_task"] = dispatch_task
                result["request_advisor_help"] = False
                result["action_history"] = [
                    f"[Planner] Compact recovery dispatch -> {dispatch_task.get('agent', 'poc')} | task={_truncate_text_for_prompt(str(dispatch_task.get('task') or ''), 220)}"
                ]
        return result

    # Advisor 节点
    async def advisor_node(state: PenetrationTesterState):
        """
        Advisor：分析当前上下文并给出建议，可按需加载技能知识。
        """
        persist_working_memory(state)
        budget = _task_budget_snapshot(state)
        min_budget_for_advisor = int(os.getenv("ADVISOR_MIN_BUDGET_SEC", "45"))
        if budget["remaining"] <= min_budget_for_advisor:
            log_system_event(
                "[Advisor] Remaining task budget too low, stopping gracefully before hard timeout",
                {
                    "remaining_seconds": round(budget["remaining"], 1),
                    "threshold": min_budget_for_advisor,
                },
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="Task budget nearly exhausted. Stop instead of launching another advisor round.")],
                "advisor_suggestion": "",
                "request_advisor_help": False,
                "is_finished": True,
                "advisor_rounds": 1,
            }

        prompt_limits = _adaptive_prompt_limits(state)

        # 构建系统提示词
        advisor_sys_prompt = ADVISOR_SYSTEM_PROMPT

        frozen_context = load_frozen_findings_for_state(
            state,
            max_chars=min(prompt_limits["work_note_chars"], 2200),
        )
        if frozen_context:
            log_system_event(
                "[Advisor] Loaded frozen findings context",
                {"challenge": (state.get("current_challenge") or {}).get("challenge_code", "unknown")},
            )
            advisor_sys_prompt += (
                "\n\n---\n\n## 冻结事实（高优先级，不可静默丢弃）\n\n"
                + frozen_context
                + "\n\n规则：若你不同意这些冻结事实，必须指出哪条确定性证据与之矛盾；否则只能做更严格确认或保留。"
            )

        should_reuse_working_memory = (
            int(state.get("no_progress_rounds", 0) or 0) >= 2
            or int(state.get("repeated_hypothesis_rounds", 0) or 0) >= 3
            or int(state.get("no_action_rounds", 0) or 0) >= 2
        )
        if should_reuse_working_memory:
            working_memory_content = load_decision_memory_for_state(
                state,
                max_chars=prompt_limits["work_note_chars"],
            )
            if working_memory_content:
                log_system_event(
                    "[Advisor] Loaded working memory for forced review",
                    {"challenge": (state.get("current_challenge") or {}).get("challenge_code", "unknown")},
                )
                advisor_sys_prompt += (
                    "\n\n---\n\n## 工作记忆（优先复核，不要重复阅读全部上下文）\n\n"
                    + working_memory_content
                )

        if _should_force_review(state):
            advisor_sys_prompt += (
                "\n\n---\n\n## 强制复盘模式\n"
                "当前流程已经出现重复假设或连续无进展。\n"
                "你现在的职责不是发散新方向，而是严格审稿：\n"
                "1. 复核当前最强假设是否证据充足；\n"
                "2. 指出当前最可能的误判点；\n"
                "3. 只给出一个可判真伪的下一步实验；\n"
                "4. 如果证据不足以继续，应明确建议 pivot 或 reject 当前假设。\n"
            )

        strategy_switch = _strategy_switch_guidance(state)
        if strategy_switch:
            advisor_sys_prompt += f"\n\n---\n\n## 策略切换提示\n{strategy_switch}\n"

        # 按需加载 Skills
        hint_content = ""
        target_info_msg = ""
        recon_context = ""
        explicit_skills: List[str] = []
        challenge_context_lines: List[str] = []
        if state.get("current_challenge"):
            challenge = state["current_challenge"]
            hint_content = challenge.get("hint_content", "")
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            target_info_msg = f"- **目标**: {ip}:{','.join(map(str, ports))}"
            challenge_context_lines.extend(
                [
                    "benchmark_target" if (challenge.get("_benchmark_target_id") and not _benchmark_priors_enabled()) else challenge.get("challenge_code", ""),
                    challenge.get("_target_url", "") or "",
                ]
            )
            if _benchmark_priors_enabled():
                challenge_context_lines.extend(
                    [
                        challenge.get("_benchmark_target_id", "") or "",
                        " ".join(challenge.get("_expected_cves", []) or []),
                        challenge.get("_expected_family", "") or "",
                    ]
                )

        for msg in state.get("messages", []):
            content = getattr(msg, "content", "")
            if isinstance(content, str) and ("系统自动侦察结果" in content or "自动侦察" in content):
                recon_context += content + "\n"

        recent_tool_context = ""
        for msg in reversed(state.get("messages", [])):
            if not isinstance(msg, ToolMessage):
                continue
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                recent_tool_context += content[:2000] + "\n"
            if len(recent_tool_context) >= 6000:
                break

        hint_and_context = "\n".join([hint_content, *challenge_context_lines]).strip()
        evidence_signal_context = f"{recon_context}\n{recent_tool_context}"
        full_signal_context = f"{hint_and_context}\n{evidence_signal_context}"
        skill_stage = _infer_skill_stage(state, evidence_signal_context)
        blocked_families = _blocked_hypothesis_families(state)

        # 按阶段强制注入技能，降低早期误触发
        if skill_stage == "recon":
            explicit_skills.extend(["pentest-master", "web-recon"])
        elif skill_stage == "transition":
            explicit_skills.append("vuln-assess")
        elif skill_stage == "vuln" and not has_actionable_confirmed_findings(state.get("findings") or []):
            explicit_skills.append("vuln-assess")

        # 仅在出现更具体的利用级证据时注入漏洞族 skill，避免仅因产品名/首页文本触发家族偏置
        if skill_stage != "recon" and _should_load_struts_ognl_skill(
            hint_and_context=hint_and_context,
            recent_tool_context=recent_tool_context,
            findings=list(state.get("findings") or []),
            last_execution_outcome=dict(state.get("last_execution_outcome") or {}),
            blocked_families=blocked_families,
        ):
            explicit_skills.append("struts2-ognl")

        finding_skill_map = {
            "rce": "rce",
            "ssti": "ssti",
            "sql_injection": "sqli",
            "xss": "xss",
            "xxe": "xxe",
            "ssrf": "ssrf",
            "file_inclusion": "file-inclusion",
            "auth_bypass": "auth-bypass",
        }
        for finding in state.get("findings", []) or []:
            if not (
                has_actionable_confirmed_findings([finding])
                or is_high_value_active_finding(finding)
            ):
                continue
            mapped = finding_skill_map.get((finding.get("vuln_type") or "").strip().lower())
            if mapped:
                explicit_skills.append(mapped)
            if (finding.get("template_id") or "").strip().lower() == "struts2_ognl_family":
                explicit_skills.append("struts2-ognl")

        explicit_skills = list(dict.fromkeys(explicit_skills))
        skill_signature = _skill_context_signature(
            skill_stage=skill_stage,
            explicit_skills=explicit_skills,
            hint_and_context=hint_and_context,
            recon_context=recon_context,
            recent_tool_context=recent_tool_context,
        )
        should_reload_skills = skill_signature != str(state.get("last_skill_context_signature") or "")

        # 加载技能内容
        skills_content = ""
        if should_reload_skills:
            skills_content = load_skills_for_context(
                hint=hint_and_context,
                response=recon_context + "\n" + recent_tool_context,
                explicit_skills=explicit_skills,
                max_skills=3,
                stage=skill_stage,
            )
        else:
            log_system_event(
                "[Advisor] Reused previous skill context signature; skip reloading skills",
                {"stage": skill_stage, "explicit_skills": explicit_skills},
            )

        if skills_content:
            max_skill_chars = prompt_limits["skill_chars"]
            skills_content = _truncate_text_for_prompt(skills_content, max_skill_chars)
            advisor_sys_prompt += f"\n\n---\n\n# 按需加载技能知识\n\n{skills_content}"
            log_system_event(
                "[Advisor] Loaded context skills",
                {"stage": skill_stage, "explicit_skills": explicit_skills},
            )

        cve_focus_candidates = _load_cve_focus_candidates(
            state,
            hint_and_context=hint_and_context,
            recent_tool_context=recent_tool_context,
            max_candidates=max(1, int(os.getenv("CVE_TASK_GUIDANCE_TOP_K", "3"))),
        )
        cve_focus_block = _format_cve_focus_candidates(
            cve_focus_candidates,
            max_chars=min(prompt_limits["rag_chars"], 1200),
        )
        if cve_focus_block:
            advisor_sys_prompt += f"\n\n---\n\n{cve_focus_block}"

        has_confirmed_findings = has_actionable_confirmed_findings(state.get("findings") or [])

        # RAG: 检索 WooYun 历史案例
        rag_query = normalize_text_content(f"{hint_and_context} {recent_tool_context[:1500]}")
        allow_rag_after_confirm = os.getenv("ENABLE_RAG_AFTER_CONFIRM", "false").strip().lower() == "true"
        advisor_loop_rounds = int(state.get("advisor_loop_rounds", 0) or 0)
        rag_allow_in_review_mode = os.getenv("RAG_ALLOW_IN_REVIEW_MODE", "true").strip().lower() == "true"
        rag_disable_after_loops = int(os.getenv("RAG_DISABLE_AFTER_ADVISOR_LOOPS", "0"))
        rag_blocked_by_review_loop = (
            rag_disable_after_loops > 0
            and advisor_loop_rounds >= rag_disable_after_loops
            and not rag_allow_in_review_mode
        )
        rag_blocked_by_review_mode = (
            (should_reuse_working_memory or _should_force_review(state))
            and not rag_allow_in_review_mode
        )
        if (
            rag_query
            and (not has_confirmed_findings or allow_rag_after_confirm)
            and not rag_blocked_by_review_loop
            and not rag_blocked_by_review_mode
            and _should_enable_rag(state, skill_stage, full_signal_context)
            and prompt_limits["rag_chars"] > 0
        ):
            rag_start = time.time()
            rag_content = retrieve_wooyun_cases(rag_query, top_k=3)
            rag_elapsed = round(time.time() - rag_start, 2)
            if rag_content:
                max_rag_chars = prompt_limits["rag_chars"]
                rag_content = _truncate_text_for_prompt(rag_content, max_rag_chars)
                advisor_sys_prompt += f"\n\n---\n\n{rag_content}"
                log_system_event("[Advisor] Loaded WooYun RAG context", {"elapsed_seconds": rag_elapsed})

        if hint_content:
            advisor_sys_prompt += f"\n## Target\n{target_info_msg}\n## Challenge Hint (Important)\n\n{hint_content}\n\n"

        advisor_messages = [SystemMessage(content=advisor_sys_prompt)]

        # submit_flag 成功判定
        context_parts = build_advisor_context(state)

        if context_parts:
            full_context = "\n".join(context_parts) + "\n\n---\n\nPlease provide attack advice based on the context above."
            advisor_messages.append(HumanMessage(content=full_context))
        else:
            advisor_messages.append(HumanMessage(content="No actionable attacker context yet; wait for more execution evidence."))

        log_agent_thought("[Advisor] Start analysis")

        try:
            configured_timeout = int(os.getenv("ADVISOR_AGENT_LLM_TIMEOUT_SEC", "150"))
            advisor_timeout_sec = _budget_aware_timeout(
                state,
                configured_timeout=configured_timeout,
                reserve_seconds=int(os.getenv("ADVISOR_BUDGET_RESERVE_SEC", "45")),
                min_timeout=int(os.getenv("ADVISOR_MIN_TIMEOUT_SEC", "20")),
            )
            async with asyncio.timeout(advisor_timeout_sec):
                advisor_response: AIMessage = await retry_llm_call(
                    advisor_llm.ainvoke,
                    advisor_messages,
                    max_retries=5,
                    base_delay=2.0,
                    limiter=advisor_limiter
                )
        except asyncio.TimeoutError:
            log_system_event(
                "[Advisor] LLM 调用超时",
                {"timeout_seconds": advisor_timeout_sec},
                level=logging.WARNING,
            )
            return {
                "advisor_suggestion": "",
                "messages": [],
                "advisor_rounds": 1,
            }
        except Exception as e:
            if is_authentication_error(e):
                error_message = (
                    "LLM authentication failed in Advisor Agent. "
                    "Please verify your configured API key/base_url/model."
                )
                log_system_event("[Advisor] Authentication failed, stop current task", {"error": str(e)}, level=logging.ERROR)
                return {
                    "messages": [AIMessage(content=error_message)],
                    "advisor_suggestion": "",
                    "is_finished": True,
                    "advisor_rounds": 1,
                }
            log_system_event(
                "[Advisor] LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "advisor_suggestion": "",
                "messages": [],
                "advisor_rounds": 1,
            }

        advisor_response = _normalize_ai_message_content(advisor_response)

        log_agent_thought(
            "[Advisor] 提供建议",
            {"advice": (advisor_response.content or "")[:200] + "..."}
        )

        hypothesis_line = _hypothesis_to_history_line("advisor", _parse_hypothesis_block(str(advisor_response.content or "")))
        advisor_suggestion = _sanitize_advisor_suggestion_for_planner(state, str(advisor_response.content or ""))

        result = {
            "advisor_suggestion": advisor_suggestion,
            "messages": [],
            "advisor_rounds": 1,
            "last_skill_context_signature": skill_signature,
        }
        if hypothesis_line:
            result["action_history"] = [hypothesis_line]
        return result

    # Main 节点
    async def main_agent_node(state: PenetrationTesterState):
        """
        Main Agent：负责规划与任务分发。
        支持输出：
        - [DISPATCH_TASK] ... [/DISPATCH_TASK]
        - [REQUEST_ADVISOR_HELP]
        - [SUBMIT_FLAG:flag{{...}}]
        """
        persist_working_memory(state)
        budget = _task_budget_snapshot(state)
        min_budget_for_main = int(os.getenv("MAIN_AGENT_MIN_BUDGET_SEC", "60"))
        if budget["remaining"] <= min_budget_for_main:
            log_system_event(
                "[Main Agent] Remaining task budget too low, stopping gracefully before hard timeout",
                {
                    "remaining_seconds": round(budget["remaining"], 1),
                    "threshold": min_budget_for_main,
                },
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="Task budget nearly exhausted. Stop instead of launching another heavy planning round.")],
                "request_advisor_help": False,
                "is_finished": True,
                "main_rounds": 1,
            }

        prompt_limits = _adaptive_prompt_limits(state)
        total_rounds = int(
            (state.get("advisor_rounds", 0) or 0)
            + (state.get("main_rounds", 0) or 0)
            + (state.get("poc_rounds", 0) or 0)
            + (state.get("docker_rounds", 0) or 0)
            + (state.get("tool_rounds", 0) or 0)
        )
        max_total_rounds = int(os.getenv("MAX_GRAPH_TOTAL_ROUNDS", "72"))
        if total_rounds >= max_total_rounds:
            log_system_event(
                "[Main Agent] Total graph rounds reached limit, stopping current task",
                {"total_rounds": total_rounds, "max_total_rounds": max_total_rounds},
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="Round budget reached. Stop current task.")],
                "request_advisor_help": False,
                "is_finished": True,
                "main_rounds": 1,
            }

        # 构建当前上下文
        current_context = build_main_context(state)

        # 构建主控提示词
        system_prompt = MAIN_AGENT_PLANNER_PROMPT.format(current_context=current_context)

        frozen_context = load_frozen_findings_for_state(
            state,
            max_chars=min(prompt_limits["work_note_chars"], 2200),
        )
        if frozen_context:
            log_system_event(
                "[Main Agent] Loaded frozen findings context",
                {"challenge": (state.get("current_challenge") or {}).get("challenge_code", "unknown")},
            )
            system_prompt += (
                "\n\n## Frozen Facts\n"
                + frozen_context
                + "\n\nRules:\n"
                "1. Frozen findings cannot be silently discarded.\n"
                "2. If you do not confirm them this round, keep them as high-value suspected findings.\n"
                "3. Only deterministic contradictory evidence may justify downgrading them.\n"
            )

        should_reuse_working_memory = (
            int(state.get("no_progress_rounds", 0) or 0) >= 2
            or int(state.get("repeated_hypothesis_rounds", 0) or 0) >= 3
            or int(state.get("no_action_rounds", 0) or 0) >= 2
        )
        if should_reuse_working_memory:
            working_memory_content = load_decision_memory_for_state(
                state,
                max_chars=prompt_limits["work_note_chars"],
            )
            if working_memory_content:
                log_system_event(
                    "[Main Agent] Loaded working memory for replanning",
                    {"challenge": (state.get("current_challenge") or {}).get("challenge_code", "unknown")},
                )
                system_prompt += (
                    "\n\n---\n\n## 工作记忆（卡住时优先用这里复盘与判伪）\n\n"
                    + working_memory_content
                )

        if _should_force_review(state):
            system_prompt += (
                "\n\n## Forced Review\n"
                "The workflow is stalled or repeating itself.\n"
                "Do not continue normal exploration.\n"
                "Either:\n"
                "1) request advisor review, or\n"
                "2) dispatch exactly one falsifiable pivot experiment with explicit PASS/FAIL criteria.\n"
            )

        strategy_switch = _strategy_switch_guidance(state)
        if strategy_switch:
            system_prompt += f"\n\n## Strategy Switch\n{strategy_switch}\n"

        challenge_context_lines: List[str] = []
        hint_content = ""
        challenge = dict(state.get("current_challenge") or {})
        if challenge:
            hint_content = str(challenge.get("hint_content") or "")
            challenge_context_lines.extend(
                [
                    "benchmark_target" if (challenge.get("_benchmark_target_id") and not _benchmark_priors_enabled()) else str(challenge.get("challenge_code") or ""),
                    str(challenge.get("_target_url") or ""),
                ]
            )
            if _benchmark_priors_enabled():
                challenge_context_lines.extend(
                    [
                        str(challenge.get("_benchmark_target_id") or ""),
                        " ".join(challenge.get("_expected_cves", []) or []),
                        str(challenge.get("_expected_family") or ""),
                    ]
                )
        hint_and_context = "\n".join([hint_content, *challenge_context_lines]).strip()
        recent_tool_context = ""
        for msg in reversed(state.get("messages", [])):
            if not isinstance(msg, ToolMessage):
                continue
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                recent_tool_context += content[:1600] + "\n"
            if len(recent_tool_context) >= 5000:
                break

        cve_focus_candidates = _load_cve_focus_candidates(
            state,
            hint_and_context=hint_and_context,
            recent_tool_context=recent_tool_context,
            max_candidates=max(1, int(os.getenv("CVE_TASK_GUIDANCE_TOP_K", "3"))),
        )
        cve_focus_block = _format_cve_focus_candidates(
            cve_focus_candidates,
            max_chars=min(prompt_limits["rag_chars"], 1200),
        )
        if cve_focus_block:
            system_prompt += f"\n\n---\n\n{cve_focus_block}\n"

        # 注入顾问建议
        advisor_suggestion = state.get("advisor_suggestion")
        if advisor_suggestion:
            max_advisor_chars = prompt_limits["advisor_chars"]
            advisor_suggestion = _truncate_text_for_prompt(advisor_suggestion, max_advisor_chars)
            system_prompt += f"""

---

## 顾问建议

{advisor_suggestion}

Please use the advisor guidance to refine your next concrete action.
"""

        repeated_hypothesis_rounds = int(state.get("repeated_hypothesis_rounds", 0) or 0)
        hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip()
        if repeated_hypothesis_rounds >= 3 and hypothesis_signature:
            system_prompt += f"""

## Hypothesis Loop Guard
You have already spent multiple rounds on the same hypothesis family: `{hypothesis_signature}`.
Do not continue with the same family unless you have a genuinely new endpoint, parameter, or runtime marker.
Prefer either:
1) one final deterministic PASS/FAIL verification, or
2) pivoting to a different family supported by stronger evidence.
"""

        history = list(state.get("messages", []))
        max_history = prompt_limits["history"]
        history = _sanitize_history_for_tool_call_chain(
            history,
            max_history,
            max_tool_content_chars=prompt_limits["tool_message_chars"],
        )

        recent_tool_names = [
            (getattr(m, "name", None) or "").strip()
            for m in history
            if isinstance(m, ToolMessage)
        ]
        docker_used = any(name == "execute_command" for name in recent_tool_names)
        poc_usage_count = sum(1 for name in recent_tool_names if name == "execute_python_poc")
        confirmed_in_state = has_actionable_confirmed_findings(state.get("findings") or [])
        last_hypothesis_family = str(state.get("last_hypothesis_signature") or "").split(":", 1)[0].strip().lower()
        if (
            poc_usage_count >= 2
            and not docker_used
            and not confirmed_in_state
            and last_hypothesis_family not in {"struts2-ognl"}
        ):
            system_prompt += """

## Execution Diversity Constraint
You have repeatedly used Python PoC without confirmed evidence.
In the next round, use an alternative execution path (`agent: docker`) only for
focused verification. Avoid broad scans and prefer one deterministic check that
can clearly confirm or reject the current top hypothesis."""

        messages = [SystemMessage(content=system_prompt)]
        messages.extend(history)

        log_agent_thought("[Main Agent] Start planning")

        try:
            configured_timeout = int(os.getenv("MAIN_AGENT_LLM_TIMEOUT_SEC", "150"))
            main_timeout_sec = _budget_aware_timeout(
                state,
                configured_timeout=configured_timeout,
                reserve_seconds=int(os.getenv("MAIN_AGENT_BUDGET_RESERVE_SEC", "60")),
                min_timeout=int(os.getenv("MAIN_AGENT_MIN_TIMEOUT_SEC", "20")),
            )
            async with asyncio.timeout(main_timeout_sec):
                ai_message: AIMessage = await retry_llm_call(
                    main_llm.ainvoke,
                    messages,
                    max_retries=5,
                    base_delay=2.0,
                    limiter=main_limiter
                )
        except asyncio.TimeoutError:
            log_system_event(
                "[Main Agent] LLM call timeout, requesting advisor review",
                {"timeout_seconds": main_timeout_sec},
                level=logging.WARNING,
            )
            compact_recovery = await _attempt_compact_main_recovery(
                state,
                reason=f"main planning timeout after {main_timeout_sec}s",
            )
            if compact_recovery:
                return compact_recovery
            return {
                "messages": [AIMessage(content="Main planning timeout [REQUEST_ADVISOR_HELP]")],
                "advisor_suggestion": "",
                "request_advisor_help": True,
                "main_rounds": 1,
            }
        except Exception as e:
            if is_authentication_error(e):
                error_message = (
                    "LLM authentication failed in Main Agent. "
                    "Please verify your configured API key/base_url/model."
                )
                log_system_event("[Main Agent] Authentication failed, stop current task", {"error": str(e)}, level=logging.ERROR)
                return {
                    "messages": [AIMessage(content=error_message)],
                    "advisor_suggestion": "",
                    "request_advisor_help": False,
                    "is_finished": True,
                    "main_rounds": 1,
                }
            if is_context_overflow_error(e):
                error_message = (
                    "LLM context overflow (413). Tool/recon/skill context has been reduced, "
                    "please retry this target. You can further lower TOOL_OUTPUT_MAX_CHARS, "
                    "RECON_HTML_MAX_CHARS, or MAX_HISTORY_MESSAGES."
                )
                log_system_event("[Main Agent] Context overflow", {"error": str(e)}, level=logging.ERROR)
                return {
                    "messages": [AIMessage(content=error_message)],
                    "advisor_suggestion": "",
                    "request_advisor_help": False,
                    "is_finished": True,
                    "main_rounds": 1,
                }
            log_system_event(
                "[Main Agent] LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            compact_recovery = await _attempt_compact_main_recovery(
                state,
                reason=f"main planning error: {str(e)}",
            )
            if compact_recovery:
                return compact_recovery
            return {
                "messages": [AIMessage(content=f"Planning failed: {str(e)} [REQUEST_ADVISOR_HELP]")],
                "advisor_suggestion": "",
                "request_advisor_help": True,
                "main_rounds": 1,
            }

        ai_message = _normalize_ai_message_content(ai_message)
        content = ai_message.content or ""

        # 鐟欙絾鐎芥潏鎾冲毉
        request_help = "[REQUEST_ADVISOR_HELP]" in content
        dispatch_task = _parse_dispatch_task(content)
        objective_mode = _objective_mode()
        submit_flag = _parse_submit_flag(content) if objective_mode == "flag" else None

        repeated_task_rounds = int(state.get("repeated_task_rounds", 0) or 0)
        last_task_signature = state.get("last_task_signature")
        repeated_hypothesis_rounds = int(state.get("repeated_hypothesis_rounds", 0) or 0)
        last_hypothesis_signature = state.get("last_hypothesis_signature")
        current_findings = list(state.get("findings") or [])
        has_confirmed_in_state = has_actionable_confirmed_findings(current_findings)
        has_suspected_in_state = has_actionable_active_findings(current_findings) and not has_confirmed_in_state
        workflow_phase = _infer_skill_stage(state, "")
        current_task_signature = None
        current_hypothesis_signature = None
        skip_auto_fallback_task = False
        if dispatch_task:
            dispatch_task = _normalize_dispatch_task_target(dispatch_task, state)
            dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
            dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
            current_task_signature = _task_signature(dispatch_task)
            current_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
            if (
                not has_confirmed_in_state
                and not has_suspected_in_state
                and workflow_phase != "vuln"
                and _is_family_specific_hypothesis_signature(current_hypothesis_signature)
                and not _should_preserve_family_specific_task(state, current_hypothesis_signature)
            ):
                replacement_task = _build_surface_pivot_task(state) or {
                    "agent": "poc",
                    "task": _focused_verification_task(state),
                }
                log_system_event(
                    "[Planner] Early family-specific task downgraded to staged verification",
                    {
                        "workflow_phase": workflow_phase,
                        "hypothesis_signature": current_hypothesis_signature,
                    },
                    level=logging.WARNING,
                )
                dispatch_task = _normalize_dispatch_task_target(replacement_task, state)
                dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
                dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
                current_task_signature = _task_signature(dispatch_task)
                current_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
            blocked_hypotheses = _blocked_hypothesis_set(state)
            if current_hypothesis_signature and current_hypothesis_signature.lower() in blocked_hypotheses:
                log_system_event(
                    "[Planner] Blocked hypothesis was proposed again; require pivot/review",
                    {"hypothesis_signature": current_hypothesis_signature},
                    level=logging.WARNING,
                )
                pivot_task = _build_surface_pivot_task(state)
                if pivot_task:
                    dispatch_task = _normalize_dispatch_task_target(pivot_task, state)
                    dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
                    dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
                    current_task_signature = _task_signature(dispatch_task)
                    current_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
                    if current_task_signature and current_task_signature == last_task_signature:
                        log_system_event(
                            "[Planner] Surface pivot produced the same task signature; escalate to advisor instead of redispatching",
                            {
                                "task_signature": current_task_signature,
                                "surface": _pick_candidate_surface_hint(state) or "N/A",
                            },
                            level=logging.WARNING,
                        )
                        dispatch_task = None
                        request_help = True
                        skip_auto_fallback_task = True
                        current_task_signature = None
                        current_hypothesis_signature = None
                        repeated_task_rounds = int(state.get("repeated_task_rounds", 0) or 0)
                        repeated_hypothesis_rounds = int(state.get("repeated_hypothesis_rounds", 0) or 0)
                    else:
                        repeated_task_rounds = 1 if current_task_signature else 0
                        repeated_hypothesis_rounds = 1 if current_hypothesis_signature else 0
                        request_help = False
                        log_system_event(
                            "[Planner] Pivoted to candidate surface after blocked hypothesis",
                            {
                                "blocked_hypothesis": state.get("last_hypothesis_signature") or "unknown",
                                "surface": _pick_candidate_surface_hint(state) or "N/A",
                            },
                        )
                else:
                    dispatch_task = None
                    request_help = True
            if current_task_signature and current_task_signature == last_task_signature:
                repeated_task_rounds += 1
            else:
                repeated_task_rounds = 1
            max_repeat_task_rounds = int(os.getenv("MAX_REPEAT_TASK_ROUNDS", "3"))
            has_confirmed = has_actionable_confirmed_findings(state.get("findings") or [])
            if current_hypothesis_signature and current_hypothesis_signature == last_hypothesis_signature:
                repeated_hypothesis_rounds += 1
            else:
                repeated_hypothesis_rounds = 1 if current_hypothesis_signature else 0
            if repeated_task_rounds >= max_repeat_task_rounds and not has_confirmed:
                log_system_event(
                    "[Planner] Repeated dispatch loop detected, switching to advisor review",
                    {
                        "task_signature": current_task_signature,
                        "repeated_task_rounds": repeated_task_rounds,
                        "max_repeat_task_rounds": max_repeat_task_rounds,
                    },
                    level=logging.WARNING,
                )
                dispatch_task = None
                request_help = True
            max_repeat_hypothesis_rounds = int(os.getenv("MAX_REPEAT_HYPOTHESIS_ROUNDS", "6"))
            prior_no_progress_rounds = int(state.get("no_progress_rounds", 0) or 0)
            if (
                dispatch_task
                and current_hypothesis_signature
                and repeated_hypothesis_rounds >= max_repeat_hypothesis_rounds
                and prior_no_progress_rounds >= 3
                and not has_confirmed
            ):
                log_system_event(
                    "[Planner] Repeated hypothesis loop detected, forcing pivot/advisor review",
                    {
                        "hypothesis_signature": current_hypothesis_signature,
                        "repeated_hypothesis_rounds": repeated_hypothesis_rounds,
                        "max_repeat_hypothesis_rounds": max_repeat_hypothesis_rounds,
                        "no_progress_rounds": prior_no_progress_rounds,
                    },
                    level=logging.WARNING,
                )
                dispatch_task = None
                request_help = True

        if (
            not dispatch_task
            and request_help
            and not has_confirmed_in_state
            and not has_suspected_in_state
            and not skip_auto_fallback_task
        ):
            tool_rounds = int(state.get("tool_rounds", 0) or 0)
            fallback_surface = _pick_candidate_surface_hint(state)
            latest_execution_outcome = dict(state.get("last_execution_outcome") or {})
            latest_tool_status = str(latest_execution_outcome.get("tool_status") or "").strip().lower()
            allow_retry_same_hypothesis = bool(latest_execution_outcome.get("should_retry_same_hypothesis"))
            transport_retry_round_window = int(os.getenv("TRANSPORT_RETRY_ROUND_WINDOW", "4"))
            transport_retry_mode = (
                allow_retry_same_hypothesis
                and latest_tool_status in {"transport_error", "partial"}
                and tool_rounds <= transport_retry_round_window
            )
            can_retry_partial = (
                (tool_rounds == 0 or transport_retry_mode)
                and _has_recent_partial_verification_signal(state)
            )
            has_surface_hint = bool(fallback_surface and fallback_surface not in {"N/A", "/", ""}) and (
                tool_rounds == 0 or transport_retry_mode
            )

            cve_fallback_max_rounds = int(os.getenv("AUTO_CVE_FALLBACK_MAX_TOOL_ROUNDS", "6"))
            top_cve_family = str((cve_focus_candidates[0] if cve_focus_candidates else {}).get("product_family") or "").strip().lower()
            hypothesis_family = str(last_hypothesis_signature or "").split(":", 1)[0].strip().lower()
            family_compatible = (
                not hypothesis_family
                or hypothesis_family in {"", "recon"}
                or hypothesis_family in top_cve_family
                or top_cve_family in hypothesis_family
            )
            should_try_cve_guided_task = bool(cve_focus_candidates) and (
                transport_retry_mode
                or tool_rounds <= cve_fallback_max_rounds
            ) and family_compatible
            if cve_focus_candidates and not family_compatible:
                log_system_event(
                    "[Planner] Skip CVE-guided fallback due family mismatch",
                    {
                        "hypothesis_family": hypothesis_family or "unknown",
                        "top_cve_family": top_cve_family or "unknown",
                        "top_cve": (cve_focus_candidates[0] or {}).get("cve"),
                    },
                    level=logging.WARNING,
                )
            if should_try_cve_guided_task and cve_focus_candidates:
                log_system_event(
                    "[Planner] Applying CVE-guided fallback task",
                    {
                        "top_cve": (cve_focus_candidates[0] or {}).get("cve"),
                        "top_family": top_cve_family or "unknown",
                        "transport_retry_mode": transport_retry_mode,
                    },
                )
            if should_try_cve_guided_task:
                dispatch_task = _build_cve_guided_verification_task(
                    state,
                    cve_focus_candidates,
                    prefer_transport_resilient=transport_retry_mode,
                )

            if not dispatch_task and has_surface_hint:
                dispatch_task = _build_surface_pivot_task(state)
            elif not dispatch_task and can_retry_partial:
                dispatch_task = {
                    "agent": "poc",
                    "task": _focused_verification_task(state),
                }

            if dispatch_task:
                dispatch_task = _normalize_dispatch_task_target(dispatch_task, state)
                dispatch_task = _stabilize_dispatch_task(dispatch_task, state)
                dispatch_task = _enforce_falsifiable_dispatch_task(dispatch_task, state)
                request_help = False
                current_task_signature = _task_signature(dispatch_task)
                current_hypothesis_signature = _infer_task_hypothesis_signature(dispatch_task)
                repeated_task_rounds = 1 if current_task_signature else 0
                repeated_hypothesis_rounds = 1 if current_hypothesis_signature else 0
                log_system_event(
                    "[Planner] Replanning produced an automatic fallback task",
                    {
                        "tool_rounds": tool_rounds,
                        "hypothesis_signature": state.get("last_hypothesis_signature") or "unknown",
                        "fallback_surface": fallback_surface or "N/A",
                        "transport_retry_mode": transport_retry_mode,
                        "latest_tool_status": latest_tool_status or "unknown",
                        "cve_guided": should_try_cve_guided_task,
                    },
                    level=logging.WARNING,
                )
            else:
                log_system_event(
                    "[Planner] Automatic fallback disabled after execution rounds; wait for advisor/model to produce a new actionable task",
                    {
                        "tool_rounds": tool_rounds,
                        "hypothesis_signature": state.get("last_hypothesis_signature") or "unknown",
                        "fallback_surface": fallback_surface or "N/A",
                        "transport_retry_mode": transport_retry_mode,
                        "latest_tool_status": latest_tool_status or "unknown",
                        "cve_guided_candidates": [item.get("cve") for item in (cve_focus_candidates or [])],
                    },
                    level=logging.WARNING,
                )

        has_action = bool(dispatch_task or submit_flag)
        no_action_rounds = 0 if has_action else (state.get("no_action_rounds", 0) + 1)

        auto_review_on_no_action_rounds = int(os.getenv("AUTO_REVIEW_ON_NO_ACTION_ROUNDS", "1"))
        if not has_action and not request_help and no_action_rounds >= auto_review_on_no_action_rounds:
            request_help = True

        advisor_loop_rounds = int(state.get("advisor_loop_rounds", 0) or 0)
        if not has_action:
            advisor_loop_rounds += 1
        else:
            advisor_loop_rounds = 0

        max_advisor_loop_rounds = int(os.getenv("MAX_ADVISOR_LOOP_ROUNDS", "4"))
        if advisor_loop_rounds >= max_advisor_loop_rounds and not dispatch_task and not submit_flag:
            log_system_event(
                "[Main Agent] Advisor review loop reached limit, stopping current task",
                {
                    "advisor_loop_rounds": advisor_loop_rounds,
                    "threshold": max_advisor_loop_rounds,
                    "hypothesis_signature": hypothesis_signature or current_hypothesis_signature or "unknown",
                },
                level=logging.WARNING,
            )
            return {
                "messages": [ai_message],
                "advisor_suggestion": "",
                "request_advisor_help": False,
                "no_action_rounds": int(state.get("no_action_rounds", 0) or 0) + 1,
                "advisor_loop_rounds": advisor_loop_rounds,
                "is_finished": True,
                "error": "advisor_review_loop_limit",
                "action_history": [
                    f"[Planner] advisor_loop_limit | hypothesis={hypothesis_signature or current_hypothesis_signature or 'unknown'}"
                ],
                "main_rounds": 1,
            }

        # If there is already an actionable task/flag, execute it first instead of re-consulting advisor.
        if dispatch_task or submit_flag:
            request_help = False
        has_confirmed_findings = has_actionable_confirmed_findings(state.get("findings") or [])
        if has_confirmed_findings and not dispatch_task and not submit_flag:
            log_system_event(
                "[Main Agent] Confirmed finding present and no further actionable task, stopping task",
                {
                    "request_help": request_help,
                    "hypothesis_signature": hypothesis_signature or current_hypothesis_signature or "unknown",
                },
                level=logging.WARNING,
            )
            return {
                "messages": [ai_message],
                "advisor_suggestion": "",
                "request_advisor_help": False,
                "is_finished": True,
                "main_rounds": 1,
                "action_history": [
                    f"[Planner] stop_after_confirmed_finding | hypothesis={hypothesis_signature or current_hypothesis_signature or 'unknown'}"
                ],
            }

        max_no_action_after_review = int(os.getenv("MAX_NO_ACTION_AFTER_REVIEW", "2"))
        if (
            not dispatch_task
            and not submit_flag
            and _should_force_review(state)
            and no_action_rounds >= max_no_action_after_review
        ):
            log_system_event(
                "[Main Agent] Forced review converged without actionable next step; stopping task",
                {
                    "no_action_rounds": no_action_rounds,
                    "threshold": max_no_action_after_review,
                    "hypothesis_signature": hypothesis_signature or current_hypothesis_signature or "unknown",
                },
                level=logging.WARNING,
            )
            return {
                "messages": [ai_message],
                "advisor_suggestion": "",
                "request_advisor_help": False,
                "no_action_rounds": no_action_rounds,
                "is_finished": True,
                "error": "forced_review_converged_without_action",
                "action_history": [
                    f"[ForcedReview] converged_without_action | hypothesis={hypothesis_signature or current_hypothesis_signature or 'unknown'}"
                ],
                "main_rounds": 1,
            }

        log_agent_thought(
            "[Main Agent] Planning result",
            {
                "has_dispatch": dispatch_task is not None,
                "has_submit": submit_flag is not None,
                "request_help": request_help,
                "no_action_rounds": no_action_rounds
            }
        )

        planner_hypothesis_line = _hypothesis_to_history_line("main", _parse_hypothesis_block(str(content or "")))

        # 组装本轮主代理输出
        result = {
            "messages": [ai_message],
            "advisor_suggestion": "",
            "request_advisor_help": request_help,
            "no_action_rounds": no_action_rounds,
            "advisor_loop_rounds": advisor_loop_rounds,
            "last_task_signature": current_task_signature if dispatch_task else state.get("last_task_signature"),
            "repeated_task_rounds": repeated_task_rounds if dispatch_task else 0,
            "last_hypothesis_signature": current_hypothesis_signature if dispatch_task else state.get("last_hypothesis_signature"),
            "repeated_hypothesis_rounds": repeated_hypothesis_rounds if dispatch_task else 0,
            "main_rounds": 1,
        }

        if dispatch_task:
            result["pending_task"] = dispatch_task
            history_lines = [
                f"[Planner] Dispatch -> {dispatch_task.get('agent', 'poc')} | hypothesis={current_hypothesis_signature or 'unknown'} | task={_truncate_text_for_prompt(str(dispatch_task.get('task') or ''), 220)}"
            ]
            if planner_hypothesis_line:
                history_lines.append(planner_hypothesis_line)
            result["action_history"] = history_lines
        elif request_help:
            history_lines = [
                f"[Planner] Forced advisor review | hypothesis={hypothesis_signature or current_hypothesis_signature or 'unknown'}"
            ]
            if planner_hypothesis_line:
                history_lines.append(planner_hypothesis_line)
            result["action_history"] = history_lines
        elif planner_hypothesis_line:
            result["action_history"] = [planner_hypothesis_line]

        if submit_flag:
            result["pending_flag"] = submit_flag

        return result

    # PoC 节点
    async def poc_agent_node(state: PenetrationTesterState):
        """
        PoC Agent：执行 Python PoC 任务。
        """
        # 优先处理待提交 flag
        pending_flag = state.get("pending_flag")
        if pending_flag:
            objective_mode = _objective_mode()

            # 仅 flag 模式才允许提交
            if submit_tool and objective_mode == "flag":
                log_system_event(f"[PoC Agent] 提交 FLAG: {pending_flag[:20]}...")
                challenge = state.get("current_challenge", {})
                challenge_code = challenge.get("challenge_code", challenge.get("code", "unknown"))

                # 构造 submit_flag 工具调用
                tool_call_id = f"submit_flag_{challenge_code}"
                ai_message = AIMessage(
                    content="",
                    tool_calls=[{
                        "id": tool_call_id,
                        "name": "submit_flag",
                        "args": {
                            "challenge_code": challenge_code,
                            "flag": pending_flag
                        }
                    }]
                )
                return {
                    "messages": [ai_message],
                    "pending_flag": None,
                    "pending_task": None,
                    "poc_rounds": 1,
                }
            log_system_event(
                "[PoC Agent] Ignored unverified FLAG claim",
                {"pending_flag_preview": pending_flag[:80], "objective_mode": objective_mode},
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="Ignored unverified FLAG claim. FLAG is recorded only after tool-based or official submit verification.")],
                "pending_flag": None,
                "pending_task": None,
                "poc_rounds": 1,
            }

        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[PoC Agent] No pending task")
            return {"messages": [], "pending_task": None, "poc_rounds": 1}

        # 组织目标信息并执行任务
        target_url = get_execution_url(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{POC_AGENT_SYSTEM_PROMPT}

---

## Current Task

{task_description}

## Target Info

- **URL**: {target_url}
{"- **Hint**: " + hint_content if hint_content else ""}

Write and execute Python PoC code to complete the task."""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="Please execute the task.")
        ]

        log_agent_thought(f"[PoC Agent] Execute task: {task_description[:100]}...")

        try:
            executor_timeout_sec = int(os.getenv("EXECUTOR_AGENT_LLM_TIMEOUT_SEC", "120"))
            async with asyncio.timeout(executor_timeout_sec):
                ai_message: AIMessage = await retry_llm_call(
                    poc_llm_with_tools.ainvoke,
                    messages,
                    max_retries=3,
                    base_delay=1.0,
                    limiter=main_limiter
                )
        except asyncio.TimeoutError:
            log_system_event(
                "[PoC Agent] LLM 调用超时",
                {"timeout_seconds": int(os.getenv("EXECUTOR_AGENT_LLM_TIMEOUT_SEC", "120"))},
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="PoC execution planning timeout")],
                "pending_task": None,
                "poc_rounds": 1,
            }
        except Exception as e:
            log_system_event(
                "[PoC Agent] LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"PoC execution failed: {str(e)}")],
                "pending_task": None,
                "poc_rounds": 1,
            }

        return {
            "messages": [ai_message],
            "pending_task": None,
            "poc_rounds": 1,
        }

    # Docker 节点
    async def docker_agent_node(state: PenetrationTesterState):
        """
        Docker Agent：执行 Kali 命令任务。
        """
        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[Docker Agent] No pending task")
            return {"messages": [], "pending_task": None, "docker_rounds": 1}

        # 组织目标信息并执行任务
        target_info = get_target_info(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{DOCKER_AGENT_SYSTEM_PROMPT}

---

## Current Task

{task_description}

## Target Info

{target_info}
{"- **Hint**: " + hint_content if hint_content else ""}

Run suitable Kali commands to complete the task."""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="Please execute the task.")
        ]

        log_agent_thought(f"[Docker Agent] Execute task: {task_description[:100]}...")

        try:
            executor_timeout_sec = int(os.getenv("EXECUTOR_AGENT_LLM_TIMEOUT_SEC", "120"))
            async with asyncio.timeout(executor_timeout_sec):
                ai_message: AIMessage = await retry_llm_call(
                    docker_llm_with_tools.ainvoke,
                    messages,
                    max_retries=3,
                    base_delay=1.0,
                    limiter=main_limiter
                )
        except asyncio.TimeoutError:
            log_system_event(
                "[Docker Agent] LLM 调用超时",
                {"timeout_seconds": int(os.getenv("EXECUTOR_AGENT_LLM_TIMEOUT_SEC", "120"))},
                level=logging.WARNING,
            )
            return {
                "messages": [AIMessage(content="Docker execution planning timeout")],
                "pending_task": None,
                "docker_rounds": 1,
            }
        except Exception as e:
            log_system_event(
                "[Docker Agent] LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"Docker execution failed: {str(e)}")],
                "pending_task": None,
                "docker_rounds": 1,
            }

        return {
            "messages": [ai_message],
            "pending_task": None,
            "docker_rounds": 1,
        }

    # Tool 节点
    async def tool_node(state: PenetrationTesterState):
        """
        统一执行工具调用（来自 PoC/Docker），并提取结构化漏洞发现。
        """
        result = await base_tool_node.ainvoke(state)
        result["tool_rounds"] = 1
        objective_mode = _objective_mode()
        raw_result_msgs = [_normalize_message_content(msg) for msg in list(result.get("messages", []) or [])]
        result["messages"] = raw_result_msgs

        # 处理提交答案成功的场景
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    if "答案正确" in msg.content:
                        # 从最近一次 submit_flag 调用回填 flag
                        messages = state.get("messages", [])
                        if messages:
                            last_message = messages[-1]
                            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                                for tool_call in last_message.tool_calls:
                                    if tool_call.get("name") == "submit_flag":
                                        submitted_flag = tool_call.get("args", {}).get("flag")
                                        if submitted_flag:
                                            result["flag"] = submitted_flag
                                            result["is_finished"] = True
                                            result["consecutive_failures"] = 0
                                            return result

        # 非 flag 模式下，也可从工具输出提取可信 flag（仅作补充）
        if objective_mode in {"hybrid", "flag"}:
            observed_flag = _extract_verified_flag_from_tool_messages(result.get("messages", []) or [])
            if observed_flag:
                result["flag"] = observed_flag
                log_system_event(
                    "[FLAG] Candidate flag extracted from tool output",
                    {"flag_preview": observed_flag[:80]},
                )
                if objective_mode == "flag":
                    result["is_finished"] = True

        # 提取结构化漏洞发现
        existing_findings = state.get("findings", []) or []
        new_findings: List[Dict] = []
        challenge = state.get("current_challenge", {}) or {}
        priors_enabled = _benchmark_priors_enabled()
        expected_cves = [x.upper() for x in (challenge.get("_expected_cves") or []) if x] if priors_enabled else []
        expected_family = (challenge.get("_expected_family") or "").strip() if priors_enabled else ""
        benchmark_target_id = challenge.get("_benchmark_target_id") if priors_enabled else None
        challenge_context_text = "\n".join(
            [
                "benchmark_target" if (challenge.get("_benchmark_target_id") and not priors_enabled) else str(challenge.get("challenge_code") or ""),
                str(challenge.get("_target_url") or ""),
                str(challenge.get("hint_content") or ""),
            ]
        ).strip()
        hypothesis_hints = [
            str(item)
            for item in list(state.get("action_history") or [])[-12:]
            if str(item).startswith("[Hypothesis/")
        ]
        if hypothesis_hints:
            challenge_context_text = "\n".join([challenge_context_text, *hypothesis_hints]).strip()
        if priors_enabled:
            challenge_context_text = "\n".join(
                [
                    challenge_context_text,
                    str(challenge.get("_benchmark_target_id") or ""),
                    " ".join(expected_cves),
                    expected_family,
                ]
            ).strip()
        candidate_msgs: List = []
        for msg in raw_result_msgs:
            # 仅处理工具消息及执行器消息
            if isinstance(msg, ToolMessage):
                candidate_msgs.append(msg)
                continue
            msg_name = (getattr(msg, "name", None) or "").strip().lower()
            if msg_name in {"execute_python_poc", "execute_command", "execute_shell"}:
                candidate_msgs.append(msg)
        for msg in candidate_msgs:
            content = getattr(msg, "content", "")
            if not isinstance(content, str) or not content.strip():
                continue
            source_tool = getattr(msg, "name", None) or "tool"
            finding = _extract_finding_from_text(
                content,
                source_tool=source_tool,
                expected_cves=expected_cves,
                expected_family=expected_family,
                benchmark_target_id=benchmark_target_id,
                context_text=challenge_context_text,
            )
            if not finding:
                continue
            dedup_key = _finding_key(finding)
            # Keep one finding per key within this execution batch.
            # Do not suppress keys already present in state: repeated evidence should update confidence/status.
            if any(_finding_key(x) == dedup_key for x in new_findings):
                continue
            new_findings.append(finding)

        confirmed_count = count_actionable_findings(existing_findings).get("confirmed", 0)
        new_actionable_count = 0
        history_updates: List[str] = []
        if new_findings:
            elapsed = max(0.0, time.time() - float(state.get("start_time", time.time())))
            assessed_all, metrics = assess_findings(
                existing_findings=existing_findings,
                incoming_findings=new_findings,
                elapsed_time=elapsed
            )
            assessed_all = _apply_evidence_grading(assessed_all)
            metrics = dict(metrics or {})
            actionable_metrics = count_actionable_findings(assessed_all)
            metrics["confirmed_count"] = actionable_metrics.get("confirmed", 0)
            metrics["suspected_count"] = actionable_metrics.get("suspected", 0)
            metrics["rejected_count"] = len([f for f in assessed_all if (f.get("status") or "").lower() == "rejected"])
            total_assessed = max(1, len(assessed_all))
            metrics["false_positive_rate"] = round(metrics["rejected_count"] / total_assessed, 4)
            existing_snapshot = {
                _finding_key(x): (
                    (x.get("status") or "").lower(),
                    round(float(x.get("score") or 0.0), 4),
                    round(float(x.get("confidence") or 0.0), 4),
                )
                for x in existing_findings
            }
            incoming_assessed: List[Dict] = []
            for item in assessed_all:
                key = _finding_key(item)
                current_sig = (
                    (item.get("status") or "").lower(),
                    round(float(item.get("score") or 0.0), 4),
                    round(float(item.get("confidence") or 0.0), 4),
                )
                if key not in existing_snapshot or existing_snapshot[key] != current_sig:
                    incoming_assessed.append(item)
            confirmed_count = actionable_metrics.get("confirmed", 0)
            new_actionable_count = len(
                [f for f in incoming_assessed if is_high_value_active_finding(f) or has_actionable_confirmed_findings([f])]
            )
            result["findings"] = incoming_assessed
            result["vulnerability_detected"] = confirmed_count > 0
            result["detection_metrics"] = metrics
            history_updates.extend(_summarize_new_findings_for_history(incoming_assessed))
            log_system_event(
                "[Detection] Structured findings captured",
                {
                    "count": len(incoming_assessed),
                    "confirmed_count": metrics.get("confirmed_count", 0),
                    "suspected_count": metrics.get("suspected_count", 0),
                    "rejected_count": metrics.get("rejected_count", 0),
                    "false_positive_rate": metrics.get("false_positive_rate", 0.0),
                    "types": [f.get("vuln_type") for f in incoming_assessed],
                    "cves": [f.get("cve") for f in incoming_assessed if f.get("cve")],
                    "downgraded": [
                        f.get("vuln_type")
                        for f in incoming_assessed
                        if str(f.get("audit_note") or "").startswith("downgraded_to_suspected")
                    ],
                    "verification_gaps": [
                        {
                            "vuln_type": f.get("vuln_type"),
                            "status": f.get("status"),
                            "gap": _verification_gap_summary(f),
                            "audit_note": f.get("audit_note"),
                        }
                        for f in incoming_assessed
                        if _verification_gap_summary(f) or f.get("audit_note")
                    ],
                }
            )

        post_confirm_rounds = int(state.get("post_confirm_rounds", 0) or 0)
        post_confirm_no_new_rounds = int(state.get("post_confirm_no_new_rounds", 0) or 0)
        if confirmed_count > 0:
            post_confirm_rounds += 1
            if new_actionable_count > 0:
                post_confirm_no_new_rounds = 0
            else:
                post_confirm_no_new_rounds += 1
        else:
            post_confirm_rounds = 0
            post_confirm_no_new_rounds = 0
        result["post_confirm_rounds"] = post_confirm_rounds
        result["post_confirm_no_new_rounds"] = post_confirm_no_new_rounds

        # detect/hybrid 模式下，不在首个 confirmed 后立即结束；
        # 至少继续若干轮，尽量发现同目标可能存在的其他漏洞。
        if objective_mode in {"detect", "hybrid"} and confirmed_count > 0:
            min_post_confirm_rounds = int(os.getenv("MIN_POST_CONFIRM_ROUNDS", "4"))
            max_post_confirm_no_new_rounds = int(os.getenv("MAX_POST_CONFIRM_NO_NEW_ROUNDS", "3"))
            max_post_confirm_rounds = int(os.getenv("MAX_POST_CONFIRM_ROUNDS", "8"))
            if (
                post_confirm_rounds >= min_post_confirm_rounds
                and post_confirm_no_new_rounds >= max_post_confirm_no_new_rounds
            ):
                result["is_finished"] = True
                log_system_event(
                    "[Detection] Post-confirmation exploration converged, stopping task",
                    {
                        "post_confirm_rounds": post_confirm_rounds,
                        "post_confirm_no_new_rounds": post_confirm_no_new_rounds,
                        "min_post_confirm_rounds": min_post_confirm_rounds,
                        "max_post_confirm_no_new_rounds": max_post_confirm_no_new_rounds,
                    },
                )
            elif post_confirm_rounds >= max_post_confirm_rounds:
                result["is_finished"] = True
                log_system_event(
                    "[Detection] Reached max post-confirmation rounds, stopping task",
                    {
                        "post_confirm_rounds": post_confirm_rounds,
                        "max_post_confirm_rounds": max_post_confirm_rounds,
                    },
                    level=logging.WARNING,
                )

        # 失败与连通性追踪
        is_failure = False
        connectivity_hits = 0
        smart_failure_enabled = os.getenv("ENABLE_SMART_FAILURE_DETECTION", "true").strip().lower() == "true"
        smart_input_max = int(os.getenv("SMART_FAILURE_MAX_CHARS", "4000"))

        tool_like_msgs = []
        for msg in raw_result_msgs:
            if isinstance(msg, ToolMessage):
                tool_like_msgs.append(msg)
                continue
            msg_name = (getattr(msg, "name", None) or "").strip().lower()
            if msg_name in {"execute_python_poc", "execute_command", "execute_shell"}:
                tool_like_msgs.append(msg)

        if smart_failure_enabled and tool_like_msgs:
            smart_failures = 0
            smart_details = []
            for msg in tool_like_msgs[-2:]:
                content = getattr(msg, "content", "")
                if not isinstance(content, str) or not content.strip():
                    continue
                tool_name = getattr(msg, "name", None) or "tool"
                if _looks_like_local_scaffolding_output(tool_name, content):
                    continue
                clipped = _truncate_text_for_prompt(content, smart_input_max)
                try:
                    fail, reason, key_info = await detect_failure_with_llm(
                        tool_output=clipped,
                        tool_name=tool_name,
                        llm=advisor_llm,
                        limiter=advisor_limiter,
                    )
                    if fail:
                        smart_failures += 1
                    smart_details.append(
                        {
                            "tool": tool_name,
                            "fail": bool(fail),
                            "reason": reason,
                            "key_info_preview": _truncate_text_for_prompt(key_info or "", 240),
                        }
                    )
                except Exception as exc:
                    log_system_event(
                        "[智能失败检测] 调用异常，回退关键字检测",
                        {"tool": tool_name, "error": str(exc)},
                        level=logging.WARNING,
                    )
                if _is_connectivity_failure_text(content):
                    connectivity_hits += 1

            if smart_details:
                log_system_event("[智能失败检测] 执行结果", {"details": smart_details})
            is_failure = smart_failures > 0
            for detail in smart_details:
                if detail.get("fail"):
                    history_updates.append(
                        f"[Failure/{detail.get('tool', 'tool')}] {detail.get('reason') or detail.get('key_info_preview') or 'semantic failure detected'}"
                    )
                else:
                    preview = str(detail.get("key_info_preview") or "").lower()
                    if any(token in preview for token in ["processing detected", "传输", "incomplete", "未形成明确成功证据", "未完成验证"]):
                        history_updates.append(
                            f"[Observation/{detail.get('tool', 'tool')}] {detail.get('reason') or detail.get('key_info_preview') or 'partial verification signal observed'}"
                        )
        else:
            if raw_result_msgs:
                for msg in raw_result_msgs:
                    if hasattr(msg, "content") and msg.content:
                        content = str(msg.content).lower()
                        # Avoid treating the fixed section marker "--- ERRORS ---" as real failure.
                        # Classify as failure only when explicit failure markers exist and no strong success signal exists.
                        positive_markers = [
                            "pass:",
                            "结论: pass",
                            "is vulnerable",
                            "漏洞存在",
                            "confirmed",
                            "x-cmd-result:",
                            "x-check: s2-045-test",
                            "x-user-name:",
                            "uid=",
                        ]
                        failure_keywords = [
                            "[-] fail",
                            "结论: fail",
                            "failed to",
                            "not vulnerable",
                            "exception",
                            "traceback",
                            "timeout",
                            "无法连接",
                            "错误:",
                            "失败",
                        ]
                        has_positive = any(kw in content for kw in positive_markers)
                        has_failure = any(kw in content for kw in failure_keywords)
                        is_failure = has_failure and not has_positive
                        if _is_connectivity_failure_text(content):
                            connectivity_hits += 1
                        if is_failure:
                            history_updates.append(
                                f"[Failure/{getattr(msg, 'name', None) or 'tool'}] {_truncate_text_for_prompt(str(getattr(msg, 'content', '') or ''), 180)}"
                            )

        progress_from_output = _has_tool_progress_signal(raw_result_msgs)
        execution_outcome = _build_execution_outcome(
            state=state,
            result=result,
            smart_details=smart_details if smart_failure_enabled and tool_like_msgs else [],
            is_failure=is_failure,
            connectivity_hits=connectivity_hits,
            progress_from_output=progress_from_output,
        )
        result["last_execution_outcome"] = execution_outcome
        result["execution_attempts"] = int(execution_outcome.get("execution_attempts", 0) or 0)

        candidate_surface_hints = _collect_candidate_surface_hints(
            state,
            raw_result_msgs,
            list(result.get("findings") or []),
        )
        existing_candidate_surface_hints = {
            str(item).strip().lower()
            for item in list(state.get("candidate_surface_hints") or [])
            if str(item).strip()
        }
        new_candidate_surface_hints = [
            item for item in candidate_surface_hints
            if item.strip().lower() not in existing_candidate_surface_hints
        ]
        if new_candidate_surface_hints:
            result["candidate_surface_hints"] = new_candidate_surface_hints[:8]
            history_updates.append(
                "[CandidateSurfaces] " + ", ".join(new_candidate_surface_hints[:4])
            )

        consecutive_failures = int(state.get("consecutive_failures", 0) or 0)
        tool_status = str(execution_outcome.get("tool_status") or "").strip().lower()
        if tool_status in {"failure", "transport_error"}:
            consecutive_failures += 1
        elif tool_status == "success":
            consecutive_failures = 0
        result["consecutive_failures"] = consecutive_failures
        connectivity_failures = state.get("connectivity_failures", 0)
        total_connectivity_failures = state.get("total_connectivity_failures", 0)
        if connectivity_hits > 0:
            connectivity_failures += 1
            total_connectivity_failures += 1
        else:
            connectivity_failures = 0
        result["connectivity_failures"] = connectivity_failures
        result["total_connectivity_failures"] = total_connectivity_failures

        hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip()
        if (
            hypothesis_signature
            and tool_status == "failure"
            and not bool(execution_outcome.get("should_retry_same_hypothesis"))
        ):
            blocked_existing = _blocked_hypothesis_set(state)
            if hypothesis_signature.lower() not in blocked_existing:
                result["blocked_hypothesis_signatures"] = [hypothesis_signature]
                history_updates.append(f"[BlockedHypothesis] {hypothesis_signature}")

        # 工具输出摘要（在提取与失败检测之后进行，避免影响漏洞判定）
        summarized_msgs = []
        for msg in raw_result_msgs:
            content = getattr(msg, "content", "")
            if not isinstance(content, str) or not content.strip():
                summarized_msgs.append(msg)
                continue
            tool_name = (getattr(msg, "name", None) or "tool")
            summarized = await _summarize_tool_output_if_needed(tool_name, content)
            if summarized == content:
                summarized_msgs.append(msg)
                continue
            if isinstance(msg, ToolMessage):
                summarized_msgs.append(
                    ToolMessage(
                        content=summarized,
                        tool_call_id=getattr(msg, "tool_call_id", ""),
                        name=getattr(msg, "name", None),
                    )
                )
            else:
                summarized_msgs.append(msg)

        result["messages"] = summarized_msgs
        progress_status = str(execution_outcome.get("progress_status") or "").strip().lower()
        prior_no_progress_rounds = int(state.get("no_progress_rounds", 0) or 0)
        if progress_status == "strong":
            no_progress_rounds = 0
        elif progress_status == "weak":
            no_progress_rounds = prior_no_progress_rounds
        else:
            no_progress_rounds = prior_no_progress_rounds + 1
            strategy_switch = _strategy_switch_guidance({**state, "no_progress_rounds": no_progress_rounds})
            if strategy_switch:
                history_updates.append(
                    "[StrategySwitch] " + _truncate_text_for_prompt(strategy_switch.replace("\n", " "), 220)
                )
        history_updates.append(
            "[ExecutionOutcome] "
            + _truncate_text_for_prompt(
                f"{execution_outcome.get('tool_status')} | "
                f"{execution_outcome.get('verification_status')} | "
                f"{execution_outcome.get('progress_status')} | "
                f"{execution_outcome.get('summary') or ''}",
                220,
            )
        )
        if history_updates:
            result["action_history"] = history_updates[:10]
        result["no_progress_rounds"] = no_progress_rounds

        max_no_progress_rounds = int(os.getenv("MAX_NO_PROGRESS_ROUNDS", "14"))
        if (
            no_progress_rounds >= max_no_progress_rounds
            and not result.get("is_finished")
            and not has_actionable_confirmed_findings(state.get("findings") or [])
        ):
            result["is_finished"] = True
            result["error"] = (
                "Execution stopped due to repeated no-progress rounds. "
                "Current strategy appears stuck; please adjust attack plan or constraints."
            )
            log_system_event(
                "[Router] No-progress threshold reached, stopping current task",
                {
                    "no_progress_rounds": no_progress_rounds,
                    "max_no_progress_rounds": max_no_progress_rounds,
                    "target": get_target_url(state),
                },
                level=logging.WARNING,
            )

        # 连通性失败阈值保护
        max_connectivity_failures = int(os.getenv("MAX_CONNECTIVITY_FAILURES", "3"))
        max_total_connectivity_failures = int(os.getenv("MAX_TOTAL_CONNECTIVITY_FAILURES", "5"))
        if (
            (
                connectivity_failures >= max_connectivity_failures
                or total_connectivity_failures >= max_total_connectivity_failures
            )
            and not (state.get("findings") or result.get("findings"))
            and not result.get("is_finished")
        ):
            result["is_finished"] = True
            result["error"] = (
                "Target appears unreachable after repeated connection failures. "
                "Please verify service status, target URL/port, and network reachability."
            )
            log_system_event(
                "[Router] Connectivity failure threshold reached, stopping current task",
                {
                    "connectivity_failures": connectivity_failures,
                    "total_connectivity_failures": total_connectivity_failures,
                    "threshold": max_connectivity_failures,
                    "total_threshold": max_total_connectivity_failures,
                    "target": get_target_url(state),
                },
                level=logging.WARNING,
            )

        return result

    def _total_agent_rounds(state: PenetrationTesterState) -> int:
        return int(
            (state.get("advisor_rounds", 0) or 0)
            + (state.get("main_rounds", 0) or 0)
            + (state.get("poc_rounds", 0) or 0)
            + (state.get("docker_rounds", 0) or 0)
            + (state.get("tool_rounds", 0) or 0)
        )

    # 路由：主代理之后
    def route_after_main(state: PenetrationTesterState) -> Literal["poc_agent", "docker_agent", "advisor", "end"]:
        """
        Main Agent 执行后的路由决策。
        """
        # Stop if task is finished.
        objective_mode = _objective_mode()
        if state.get("is_finished"):
            return "end"
        if objective_mode == "flag" and state.get("flag"):
            return "end"

        findings = state.get("findings") or []
        actionable_counts = count_actionable_findings(findings)
        has_confirmed = actionable_counts.get("confirmed", 0) > 0
        has_suspected = actionable_counts.get("suspected", 0) > 0
        has_valuable_findings = has_confirmed or has_suspected

        # Hard cap total graph rounds to avoid hitting LangGraph recursion limit.
        total_rounds = _total_agent_rounds(state)
        max_total_rounds = int(os.getenv("MAX_GRAPH_TOTAL_ROUNDS", "72"))
        if total_rounds >= max_total_rounds:
            log_system_event(
                "[Router] Total graph rounds reached limit, stopping current task",
                {"total_rounds": total_rounds, "max_total_rounds": max_total_rounds},
                level=logging.WARNING,
            )
            return "end"

        # Stop before LangGraph recursion limit to avoid GraphRecursionError.
        tool_rounds = int(state.get("tool_rounds", 0) or 0)
        max_tool_rounds = int(os.getenv("MAX_TOOL_ROUNDS", "24"))
        if tool_rounds >= max_tool_rounds:
            log_system_event(
                "[Router] tool_rounds reached limit, stopping current task",
                {"tool_rounds": tool_rounds, "max_tool_rounds": max_tool_rounds},
                level=logging.WARNING,
            )
            return "end"

        # Stop infinite Main<->Advisor ping-pong when Main provides no actionable output.
        max_no_action_rounds = int(os.getenv("NO_ACTION_MAX_ROUNDS", "5"))
        effective_no_action_limit = max_no_action_rounds + 2 if has_valuable_findings else max_no_action_rounds
        if state.get("no_action_rounds", 0) >= effective_no_action_limit:
            log_system_event(
                "[Router] No-action planning rounds reached limit, stopping current task",
                {
                    "no_action_rounds": state.get("no_action_rounds", 0),
                    "max_no_action_rounds": effective_no_action_limit,
                    "has_valuable_findings": has_valuable_findings,
                },
                level=logging.WARNING
            )
            return "end"

        max_advisor_loop_rounds = int(os.getenv("MAX_ADVISOR_LOOP_ROUNDS", "4"))
        effective_advisor_loop_limit = max_advisor_loop_rounds + 2 if has_valuable_findings else max_advisor_loop_rounds
        if state.get("advisor_loop_rounds", 0) >= effective_advisor_loop_limit:
            log_system_event(
                "[Router] Advisor review loop reached limit, stopping current task",
                {
                    "advisor_loop_rounds": state.get("advisor_loop_rounds", 0),
                    "max_advisor_loop_rounds": effective_advisor_loop_limit,
                    "has_valuable_findings": has_valuable_findings,
                },
                level=logging.WARNING,
            )
            return "end"

        # 优先分发待执行任务
        pending_task = state.get("pending_task")
        if pending_task:
            agent = pending_task.get("agent", "poc")
            if agent == "docker":
                log_system_event("[Router] Dispatch task to Docker Agent")
                return "docker_agent"
            else:
                log_system_event("[Router] Dispatch task to PoC Agent")
                return "poc_agent"

        # 若存在待提交 flag，交给 PoC 节点处理
        pending_flag = state.get("pending_flag")
        if pending_flag:
            return "poc_agent"

        if state.get("request_advisor_help"):
            return "advisor"

        # 默认回到 advisor 获取下一步策略
        return "advisor"

    def route_after_execution(state: PenetrationTesterState) -> Literal["tools", "main_agent", "end"]:
        """
        PoC/Docker Agent 执行后的路由决策。
        """
        # 完成态直接结束
        objective_mode = _objective_mode()
        if state.get("is_finished"):
            return "end"
        if objective_mode == "flag" and state.get("flag"):
            return "end"

        total_rounds = _total_agent_rounds(state)
        max_total_rounds = int(os.getenv("MAX_GRAPH_TOTAL_ROUNDS", "72"))
        if total_rounds >= max_total_rounds:
            log_system_event(
                "[Router] Total graph rounds reached limit, stopping current task",
                {"total_rounds": total_rounds, "max_total_rounds": max_total_rounds},
                level=logging.WARNING,
            )
            return "end"

        # 若有工具调用，进入 tools 节点
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                return "tools"

        # 否则返回主代理继续规划
        return "main_agent"

    def route_after_tools(state: PenetrationTesterState) -> Literal["main_agent", "advisor", "end"]:
        """
        tools 节点执行后的路由决策。
        """
        # 完成态直接结束
        objective_mode = _objective_mode()
        if state.get("is_finished"):
            return "end"
        if objective_mode == "flag" and state.get("flag"):
            return "end"

        findings = state.get("findings") or []
        actionable_counts = count_actionable_findings(findings)
        has_confirmed = actionable_counts.get("confirmed", 0) > 0
        has_suspected = actionable_counts.get("suspected", 0) > 0
        has_valuable_findings = has_confirmed or has_suspected

        total_rounds = _total_agent_rounds(state)
        max_total_rounds = int(os.getenv("MAX_GRAPH_TOTAL_ROUNDS", "72"))
        if total_rounds >= max_total_rounds:
            log_system_event(
                "[Router] Total graph rounds reached limit, stopping current task",
                {"total_rounds": total_rounds, "max_total_rounds": max_total_rounds},
                level=logging.WARNING,
            )
            return "end"

        # 保护递归深度，限制工具轮次
        # Guard recursion depth with an explicit tool-round limit.
        tool_rounds = int(state.get("tool_rounds", 0) or 0)
        max_tool_rounds = int(os.getenv("MAX_TOOL_ROUNDS", "24"))
        effective_tool_limit = max_tool_rounds + 4 if has_valuable_findings else max_tool_rounds
        if tool_rounds >= effective_tool_limit:
            log_system_event(
                "[Router] tool_rounds reached limit, stopping current task",
                {
                    "tool_rounds": tool_rounds,
                    "max_tool_rounds": effective_tool_limit,
                    "has_valuable_findings": has_valuable_findings,
                },
                level=logging.WARNING,
            )
            return "end"

        attempts = int(state.get("execution_attempts", 0) or 0)
        execution_outcome = dict(state.get("last_execution_outcome", {}) or {})

        from shell_agent.core.constants import AgentConfig
        max_attempts = AgentConfig.get_max_attempts()
        effective_max_attempts = max_attempts + 5 if has_valuable_findings else max_attempts

        if attempts >= effective_max_attempts:
            log_system_event(
                "[Router] Max attempts reached",
                {
                    "attempts": attempts,
                    "max_attempts": effective_max_attempts,
                    "has_valuable_findings": has_valuable_findings,
                },
                level=logging.WARNING,
            )
            return "end"

        if (
            bool(execution_outcome.get("should_retry_same_hypothesis"))
            and not has_confirmed
        ):
            return "main_agent"

        # 连续失败达到阈值时回 advisor 调整策略
        consecutive_failures = state.get("consecutive_failures", 0)
        from shell_agent.core.constants import SmartRoutingConfig
        failures_threshold = SmartRoutingConfig.get_failures_threshold()
        consultation_interval = SmartRoutingConfig.get_consultation_interval()
        effective_failures_threshold = failures_threshold + 2 if has_valuable_findings else failures_threshold

        if consecutive_failures > 0 and consecutive_failures % effective_failures_threshold == 0:
            return "advisor"

        if _should_force_review(state):
            return "advisor"

        # 定期咨询 Advisor，避免主流程长时间陷入局部策略。
        if consultation_interval > 0 and attempts > 0 and attempts % consultation_interval == 0:
            return "advisor"

        # 默认回主代理
        return "main_agent"

    # 构建工作流图
    workflow = StateGraph(PenetrationTesterState)

    # 注册节点
    workflow.add_node("advisor", advisor_node)
    workflow.add_node("main_agent", main_agent_node)
    workflow.add_node("poc_agent", poc_agent_node)
    workflow.add_node("docker_agent", docker_agent_node)
    workflow.add_node("tools", tool_node)

    # 入口节点
    workflow.set_entry_point("advisor")

    # 固定边与条件边
    workflow.add_edge("advisor", "main_agent")

    workflow.add_conditional_edges(
        "main_agent",
        route_after_main,
        {
            "poc_agent": "poc_agent",
            "docker_agent": "docker_agent",
            "advisor": "advisor",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "poc_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "docker_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "tools",
        route_after_tools,
        {
            "main_agent": "main_agent",
            "advisor": "advisor",
            "end": END
        }
    )

    # 编译图
    app = workflow.compile(store=memory_store, name=graph_name)

    log_system_event("[Graph V2] Three-layer graph build complete")
    return app


# 解析与辅助函数

# Helper logic moved to graph_findings.py / graph_tasks.py.


def _parse_submit_flag(content: str) -> Optional[str]:
    """Parse submit-flag marker from planner output."""
    import re

    pattern = r'\[SUBMIT_FLAG:(.*?)\]'
    match = re.search(pattern, content)

    if match:
        return match.group(1).strip()

    return None


# 兼容旧调用：注入外部 LLM 构建图

async def build_multi_agent_graph_with_llms(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    使用外部传入的主攻模型与思考模型构建多智能体图。

    Args:
        main_llm: 主攻模型 LLM
        advisor_llm: 思考/顾问模型 LLM
        manual_mode: 是否启用手动模式
        graph_name: 图名称（也作为 Langfuse trace 名称）
    """
    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode, graph_name=graph_name)


