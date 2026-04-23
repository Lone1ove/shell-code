from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from shell_agent.common import has_actionable_confirmed_findings, log_system_event, normalize_text_content
from shell_agent.graph_findings import _looks_like_local_scaffolding_output
from shell_agent.prompts_book import get_execution_url, get_target_url


def _truncate_text_for_prompt(text: str, max_chars: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 18)] + "...[TRUNCATED]..."


def _parse_dispatch_task(content: str) -> Optional[dict]:
    """Parse dispatch task block from planner output."""
    import re

    pattern = r'\[DISPATCH_TASK\]\s*agent:\s*(\w+)\s*task:\s*\|?\s*(.*?)\[/DISPATCH_TASK\]'
    match = re.search(pattern, content, re.DOTALL)

    if match:
        return {
            "agent": match.group(1).strip().lower(),
            "task": match.group(2).strip()
        }

    # Fallback parser: tolerate minor formatting drift in model output.
    block_match = re.search(r"\[DISPATCH_TASK\](.*?)\[/DISPATCH_TASK\]", content, re.DOTALL | re.IGNORECASE)
    if not block_match:
        return None

    block = block_match.group(1).strip()
    if not block:
        return None

    agent_match = re.search(r"(?im)^\s*agent\s*:\s*([a-zA-Z_][\w-]*)\s*$", block)
    task_match = re.search(r"(?is)\btask\s*:\s*\|?\s*(.+)$", block)
    if not task_match:
        return None

    agent = (agent_match.group(1).strip().lower() if agent_match else "poc")
    task = task_match.group(1).strip()
    if not task:
        return None
    if agent not in {"poc", "docker"}:
        agent = "poc"
    return {"agent": agent, "task": task}

    


def _normalize_dispatch_task_target(task: Dict, state: PenetrationTesterState) -> Dict:
    """
    Keep task target aligned with the current challenge target.
    Prevents planner drift to unrelated URLs/ports during long loops.
    """
    target = (get_execution_url(state) or get_target_url(state) or "").strip()
    if not target:
        return task

    task_text = (task or {}).get("task", "")
    if not isinstance(task_text, str) or not task_text.strip():
        return task

    urls = re.findall(r"https?://[^\s'\"`]+", task_text)
    if not urls:
        return task

    target_parsed = urlparse(target)
    target_scheme = (target_parsed.scheme or "http").lower()
    target_host = (target_parsed.hostname or "").strip().lower()
    target_port = target_parsed.port or (443 if target_scheme == "https" else 80)
    if not target_host:
        return task

    def _origin_tuple(url: str):
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").strip().lower()
        if not scheme or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port

    target_origin = (target_scheme, target_host, target_port)
    if any(_origin_tuple(u) == target_origin for u in urls):
        return task

    def _rewrite_origin(url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return url
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        return f"{target_scheme}://{target_host}:{target_port}{path}{query}{fragment}"

    new_text = task_text
    for u in urls:
        new_text = new_text.replace(u, _rewrite_origin(u))

    normalized = dict(task)
    normalized["task"] = new_text
    log_system_event(
        "[Planner] Normalized task target URL to current challenge target",
        {"from_urls": urls[:5], "to_url": target},
        level=logging.WARNING,
    )
    return normalized


def _task_contains_high_noise_scan(task_text: str) -> bool:
    lower = (task_text or "").lower()
    high_noise_markers = [
        "nikto ",
        "gobuster ",
        "dirb ",
        "ffuf ",
        "wfuzz ",
        "feroxbuster ",
        "masscan ",
        "nmap -p-",
        "nmap --script vuln",
        "nmap --script=default,vuln",
        "wpscan ",
        "hydra ",
    ]
    return any(marker in lower for marker in high_noise_markers)


def _is_family_specific_hypothesis_signature(signature: str) -> bool:
    raw = str(signature or "").strip().lower()
    if not raw:
        return False
    family = raw.split(":", 1)[0].strip()
    return family not in {"", "recon"}


def _candidate_surface_from_state(state: Dict) -> str:
    candidates = [str(item).strip() for item in list(state.get("candidate_surface_hints") or []) if str(item).strip()]
    if not candidates:
        return ""

    scored: List[tuple[int, str]] = []
    for text in candidates:
        normalized = text
        if text.startswith("http://") or text.startswith("https://"):
            try:
                parsed = urlparse(text)
                normalized = parsed.path or ""
                if parsed.query:
                    normalized += f"?{parsed.query}"
            except Exception:
                normalized = text
        lower = normalized.lower()
        if not lower or lower in {"/", "/index", "/home"}:
            continue
        score = 0
        if any(marker in lower for marker in [".action", ".jsp", ".php", ".do"]):
            score += 4
        if any(marker in lower for marker in ["/api/", "/upload", "/login", "/admin", "/debug", "/console"]):
            score += 3
        if "?" in lower:
            score += 2
        if lower.count("/") >= 2:
            score += 1
        scored.append((score, normalized))

    if not scored:
        return ""
    scored.sort(key=lambda x: (x[0], len(x[1])), reverse=True)
    return scored[0][1]


def _focused_verification_task(state: PenetrationTesterState) -> str:
    target = get_execution_url(state) or get_target_url(state) or "target"
    active_findings = [f for f in (state.get("findings") or []) if (f.get("status") or "").strip().lower() in {"confirmed", "suspected"}]
    hypothesis_signature = str(state.get("last_hypothesis_signature") or "").strip()
    candidate_surface = _candidate_surface_from_state(state)
    primary_surface = candidate_surface.split(";", 1)[0] if candidate_surface else ""
    last_execution_outcome = dict(state.get("last_execution_outcome") or {})
    latest_tool_status = str(last_execution_outcome.get("tool_status") or "").strip().lower()
    retry_same_hypothesis = bool(last_execution_outcome.get("should_retry_same_hypothesis"))
    struts_focus = False

    if active_findings:
        top = max(active_findings, key=lambda x: float(x.get("score") or x.get("confidence") or 0.0))
        top_type = str(top.get("vuln_type") or "unknown").strip().lower()
        top_template = str(top.get("template_id") or "").strip().lower()
        top_cve = str(top.get("cve") or "").strip().upper()
        summary = top_cve or top_template or top_type or "strongest observed hypothesis"
        cve_hint = f"Prioritize verification for the strongest observed hypothesis: {summary}."
        struts_focus = (
            top_template == "struts2_ognl_family"
            or top_cve in {"CVE-2017-5638", "CVE-2018-11776", "CVE-2017-9805"}
            or "struts" in summary.lower()
            or "ognl" in summary.lower()
        )
    elif candidate_surface:
        cve_hint = f"Prioritize surface-focused verification for the evidenced candidate surface: {candidate_surface}."
    elif hypothesis_signature:
        if _is_family_specific_hypothesis_signature(hypothesis_signature):
            cve_hint = "Prioritize one concrete endpoint or parameter already evidenced by reconnaissance, and verify it with deterministic runtime evidence."
            if any(token in hypothesis_signature.lower() for token in ["struts", "ognl", "s2-"]):
                struts_focus = True
        else:
            cve_hint = f"Prioritize verification for the current hypothesis signature: {hypothesis_signature}."
    else:
        cve_hint = "Prioritize one concrete endpoint or parameter already evidenced by reconnaissance, and verify it with deterministic runtime evidence."

    struts_requirements = (
        "6) For Struts2/OGNL path, avoid arithmetic-only checks (e.g., 111+111 -> 222).\n"
        "7) Prefer deterministic header-marker verification: baseline request must NOT contain marker header, "
        "then exploit request should create a unique response header marker.\n"
        "8) If header-marker path fails, use one command-output marker path (uid=/whoami) and stop.\n"
        if struts_focus
        else ""
    )

    return (
        f"Target: {target}\n"
        "Run ONE focused verification attempt.\n"
        f"{cve_hint}\n"
        "Requirements:\n"
        "1) Use a deterministic runtime marker (e.g., uid=/whoami/known deterministic output).\n"
        "1a) Do not rely on single-digit arithmetic echoes or generic page tokens as proof.\n"
        "2) Print request target, payload, status code, and short evidence snippet.\n"
        "3) Output explicit PASS or FAIL with reason.\n"
        "4) If FAIL, stop and return failure evidence.\n"
        "5) Do NOT run broad scans or endpoint brute force in this round.\n"
        + (
            f"6) Use `{candidate_surface}` as the primary verification endpoint (optional canonical fallback `{primary_surface}` only); "
            "do not switch to guessed sibling endpoints such as /upload or /api/upload unless they are exactly this surface.\n"
            if candidate_surface
            else ""
        )
        + (
            "7) If transport/read issues occur (e.g., IncompleteRead/RemoteDisconnected), "
            "retry the SAME request up to 3 times with short backoff before concluding FAIL.\n"
            if retry_same_hypothesis and latest_tool_status in {"transport_error", "partial"}
            else ""
        )
        + struts_requirements
    )


def _narrow_dispatch_task(task_text: str, *, reason: str) -> str:
    guidance = (
        "\n\nTask refinement guard:\n"
        f"- Reason: {reason}\n"
        "- Keep the planner-selected endpoint, parameter, path, or action if one is already named.\n"
        "- Narrow this round to exactly one endpoint and one hypothesis.\n"
        "- Prefer deterministic runtime or response-header evidence over broad enumeration.\n"
        "- Output explicit PASS and FAIL criteria.\n"
    )
    return task_text.rstrip() + guidance


def _task_contains_low_entropy_probe(task_text: str) -> bool:
    lower = normalize_text_content(task_text).lower()
    weak_probe_markers = [
        "${1+1}",
        "{{1+1}}",
        "%{1+1}",
        "{{7*7}}",
        "{{233*233}}",
        "baseline contains '2'",
        "response contains '2'",
        "contains '2': true",
        "contains \"2\": true",
        "look for 2 in response",
        "compare whether 2 appears",
        "${(111+111)}",
        "%{(111+111)}",
        "111+111",
        "grep -o \"222\"",
        "grep -o '222'",
        "echo \"pass\" || echo \"fail\"",
        "echo 'pass' || echo 'fail'",
    ]
    if any(marker in lower for marker in weak_probe_markers):
        return True
    # Arithmetic-only OGNL probe (for example %{(x+y)}) is too weak for final verification.
    if re.search(r"%\{\(\d+\s*\+\s*\d+\)\}", lower):
        return True
    if re.search(r"\$\{\(\d+\s*\+\s*\d+\)\}", lower):
        return True
    return False


def _stabilize_dispatch_task(task: Dict, state: PenetrationTesterState) -> Dict:
    """
    Stabilize planner output by suppressing high-noise broad scans in early rounds.
    Keeps the workflow focused on deterministic verification first.
    """
    if not isinstance(task, dict):
        return task

    task_text = str(task.get("task") or "")
    if not task_text.strip():
        return task

    max_task_chars = int(os.getenv("DISPATCH_TASK_MAX_CHARS", "2200"))
    if len(task_text) > max_task_chars:
        task = dict(task)
        task["task"] = _truncate_text_for_prompt(task_text, max_task_chars)
        task_text = task["task"]

    has_confirmed = has_actionable_confirmed_findings(state.get("findings") or [])
    if has_confirmed:
        return task

    tool_rounds = int(state.get("tool_rounds", 0) or 0)
    execution_attempts = int(state.get("execution_attempts", 0) or tool_rounds or 0)
    has_existing_findings = bool(state.get("findings") or [])
    early_round_limit = int(os.getenv("HIGH_NOISE_EARLY_ROUND_LIMIT", "12"))
    if _task_contains_high_noise_scan(task_text) and tool_rounds < early_round_limit:
        stabilized = dict(task)
        stabilized["task"] = _narrow_dispatch_task(
            task_text,
            reason="high-noise broad scan suppressed in early rounds",
        )
        log_system_event(
            "[Planner] High-noise task narrowed in early rounds instead of replacing planner hypothesis",
            {
                "tool_rounds": tool_rounds,
                "early_round_limit": early_round_limit,
                "original_task_preview": task_text[:240],
            },
            level=logging.WARNING,
        )
        return stabilized

    if _task_contains_low_entropy_probe(task_text):
        stabilized = dict(task)
        if execution_attempts <= 1 and not has_existing_findings:
            stabilized["agent"] = "poc"
            stabilized["task"] = _focused_verification_task(state)
        else:
            stabilized["task"] = _narrow_dispatch_task(
                task_text,
                reason="low-entropy probe preserved but narrowed to avoid overriding the planner-selected hypothesis",
            )
        log_system_event(
            "[Planner] Low-entropy verification task stabilized",
            {
                "execution_attempts": execution_attempts,
                "has_existing_findings": has_existing_findings,
                "original_task_preview": task_text[:240],
            },
            level=logging.WARNING,
        )
        return stabilized

    return task


def _task_signature(task: Dict) -> str:
    """
    Build a stable signature for dispatched tasks to detect planner loops.
    """
    if not isinstance(task, dict):
        return ""

    agent = str(task.get("agent") or "").strip().lower()
    task_text = str(task.get("task") or "").strip().lower()
    if not agent and not task_text:
        return ""

    task_text = re.sub(r"\s+", " ", task_text)

    # Collapse concrete URLs so tiny URL drift does not bypass duplicate detection.
    if task_text:
        task_text = re.sub(r"https?://[^\s'\"`]+", "<target_url>", task_text)

    digest = hashlib.sha1(f"{agent}|{task_text}".encode("utf-8", errors="ignore")).hexdigest()
    return f"{agent}:{digest[:16]}"


def _extract_final_verdict(content: str) -> str:
    text = normalize_text_content(content)
    if not text:
        return "unknown"
    lower = text.lower()
    matches: List[tuple[int, str]] = []
    patterns = [
        r"\bverdict\s*[:=\]]\s*(pass|fail)\b",
        r"\bresult\s*[:=\]]\s*(pass|fail)\b",
        r"\bfinal result\s*[:=]\s*(pass|fail)\b",
        r"\[结论\]\s*(pass|fail)\b",
        r"结论\s*[:：]\s*(pass|fail)\b",
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, lower, flags=re.IGNORECASE):
            matches.append((m.start(), m.group(1).lower()))
    if not matches:
        return "unknown"
    matches.sort(key=lambda x: x[0])
    return matches[-1][1]


def _has_tool_progress_signal(messages: List) -> bool:
    """
    Check whether recent tool outputs contain concrete verification progress.
    Recon success or generic HTTP reachability must not be treated as exploit progress.
    """
    if not messages:
        return False

    positive_markers = [
        "vulnerable",
        '"vulnerable": true',
        "exploit success",
        "successfully exploited",
        "vulnerability confirmed",
        "result: pass",
        "verdict: pass",
        "uid=",
        "gid=",
        "root:x:",
        "flag{",
        "x-ognl-test:",
        "x-cmd-result:",
        "x-user-name:",
        "response header contains",
        "command execution successful",
    ]
    negative_markers = [
        "error",
        "exception",
        "failed",
        "blocked",
        "not vulnerable",
        '"vulnerable": false',
        "connection refused",
        "timed out",
        "timeout",
        "max retries exceeded",
        "404 not found",
        "403 forbidden",
        "method not allowed",
        "no vulnerability",
        "no flag found",
        "response does not contain",
        "could not find",
        "no command execution detected",
        "baseline contains",
        "response contains '2'",
        "contains '2': true",
        "incompleteread",
        "surface verification",
        "surface-pivot verification",
        "endpoint accepts multipart",
        "controllable upload surface",
        "upload-related keywords found",
        "contains file input",
        "contains multipart enctype",
        "found input fields:",
    ]

    for msg in messages:
        content = getattr(msg, "content", "")
        tool_name = getattr(msg, "name", None) or "tool"
        if not isinstance(content, str):
            continue
        if _looks_like_local_scaffolding_output(tool_name, content):
            continue
        lower = content.lower()
        if not lower.strip():
            continue

        final_verdict = _extract_final_verdict(content)
        if final_verdict == "fail":
            continue
        if final_verdict == "pass":
            return True

        has_positive = any(marker in lower for marker in positive_markers)
        has_negative = any(marker in lower for marker in negative_markers)

        if has_positive and not has_negative:
            return True

    return False


def _is_connectivity_failure_text(text: str) -> bool:
    lower = (text or "").lower()
    markers = [
        "connection refused",
        "failed to establish a new connection",
        "max retries exceeded",
        "connection broken",
        "incomplete read",
        "incompleteread",
        "remote end closed connection",
        "remotedisconnected",
        "chunkedencodingerror",
        "protocolerror",
        "connection aborted",
        "read timed out",
        "readtimeout",
        "winerror 10061",
        "name or service not known",
        "temporary failure in name resolution",
        "network is unreachable",
        "连接失败",
        "无法连接",
        "拒绝连接",
    ]
    return any(m in lower for m in markers)
