from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from shell_agent.common import calibrated_finding_probability, has_strong_verification_signal, is_high_value_active_finding


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def working_memory_dir() -> Path:
    path = _project_root() / "intermediate_process"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _challenge_code_from_state(state: Dict) -> str:
    challenge = state.get("current_challenge") or {}
    return str(challenge.get("challenge_code") or challenge.get("code") or "unknown")


def _safe_name(challenge_code: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in challenge_code)


def working_memory_path(challenge_code: str) -> Path:
    return working_memory_dir() / f"{_safe_name(challenge_code)}.md"


def working_memory_json_path(challenge_code: str) -> Path:
    return working_memory_dir() / f"{_safe_name(challenge_code)}.json"


def clear_working_memory(challenge_code: str) -> None:
    for path in (working_memory_path(challenge_code), working_memory_json_path(challenge_code)):
        if path.exists():
            path.unlink()


def reset_transient_working_memory(challenge_code: str) -> None:
    """
    Reset per-run planner state while preserving durable findings/evidence.
    This prevents stale candidate surfaces, blocked hypotheses, and loop counters
    from a previous run from biasing a new run on the same target.
    """
    if not challenge_code:
        return

    memory = _load_structured_memory(challenge_code)
    if not memory:
        return

    counters = dict(memory.get("counters") or {})
    for key in [
        "consecutive_failures",
        "no_progress_rounds",
        "no_action_rounds",
        "advisor_loop_rounds",
        "repeated_task_rounds",
        "repeated_hypothesis_rounds",
        "confirmed_count",
        "suspected_count",
    ]:
        counters[key] = 0

    memory["execution_attempts"] = 0
    memory["counters"] = counters
    memory["current_hypothesis_signature"] = "N/A"
    memory["candidate_surface_hints"] = []
    memory["blocked_hypothesis_signatures"] = []
    memory["last_execution_outcome"] = {}
    memory["action_history"] = []
    memory["errors"] = []
    memory["updated_at"] = datetime.now().isoformat(timespec="seconds")

    json_path = working_memory_json_path(challenge_code)
    json_path.write_text(json.dumps(memory, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path = working_memory_path(challenge_code)
    md_path.write_text(build_working_memory_markdown(memory), encoding="utf-8")


def _truncate(text: str, max_chars: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 32)] + "\n...[TRUNCATED]..."


def _finding_target(finding: Dict) -> str:
    return str(
        finding.get("target_url")
        or finding.get("endpoint")
        or finding.get("target")
        or finding.get("matched_url")
        or "N/A"
    ).strip()


def _finding_key(finding: Dict) -> str:
    return "|".join(
        [
            str(finding.get("vuln_type") or "unknown").strip().lower(),
            str(_finding_target(finding)).strip().lower(),
            str(finding.get("cve") or "").strip().upper(),
            str(finding.get("template_id") or "").strip().lower(),
        ]
    )


def _normalize_memory_snippet(text: str, max_chars: int = 220) -> str:
    return _truncate(str(text).strip().replace("\r", " ").replace("\n", " "), max_chars)


def _looks_like_fake_positive_evidence(text: str, finding: Optional[Dict] = None) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    lower = raw.lower()
    positive_markers = [
        "pass: ognl injection successful",
        "[+] pass",
        "vulnerability confirmed",
        "response header injection successful",
        "ognl injection successful",
    ]
    negative_markers = [
        "result: fail",
        "verdict: fail",
        "not vulnerable",
        "no command injection vulnerability detected",
        "no 'uid=' markers found",
        "no uid= markers found",
        "no command output",
        "x-ognl header present: false",
        "header present: false",
        "connection broken",
        "incompleteread",
        "未检测到",
        "未发现",
    ]
    if any(marker in lower for marker in positive_markers) and any(marker in lower for marker in negative_markers):
        return True
    if not isinstance(finding, dict):
        return False
    status = str(finding.get("status") or "").strip().lower()
    checks = dict(finding.get("verification_checks") or {})
    if (
        status != "confirmed"
        and not bool(finding.get("strict_verified"))
        and not bool(checks.get("runtime_signal"))
        and not bool(checks.get("explicit_success_signal"))
        and any(marker in lower for marker in positive_markers)
    ):
        return True
    return False


def _sanitize_memory_snippet(text: str, finding: Optional[Dict] = None, max_chars: int = 220) -> str:
    raw = str(text or "").strip()
    if not raw or _looks_like_fake_positive_evidence(raw, finding=finding):
        return ""
    return _normalize_memory_snippet(raw, max_chars=max_chars)


def _finding_evidence_preview(finding: Dict) -> str:
    candidates = [
        finding.get("evidence"),
        finding.get("request_evidence"),
        finding.get("response_evidence"),
        finding.get("reason"),
    ]
    for item in candidates:
        if isinstance(item, str) and item.strip():
            sanitized = _sanitize_memory_snippet(item, finding=finding, max_chars=220)
            if sanitized:
                return sanitized
    return ""


def _normalized_execution_outcome(outcome: Optional[Dict]) -> Dict:
    if not isinstance(outcome, dict):
        return {}
    return {
        "tool_status": str(outcome.get("tool_status") or "").strip().lower(),
        "verification_status": str(outcome.get("verification_status") or "").strip().lower(),
        "progress_status": str(outcome.get("progress_status") or "").strip().lower(),
        "summary": _truncate(str(outcome.get("summary") or "").strip(), 240),
        "should_retry_same_hypothesis": bool(outcome.get("should_retry_same_hypothesis")),
        "connectivity_issue": bool(outcome.get("connectivity_issue")),
        "execution_attempts": int(outcome.get("execution_attempts", 0) or 0),
    }


def _is_memory_worthy_finding(finding: Dict) -> bool:
    if not isinstance(finding, dict):
        return False
    status = str(finding.get("status") or "unknown").strip().lower()
    existence_rate = float(finding.get("existence_rate") or calibrated_finding_probability(finding) or 0.0)
    has_evidence = bool(finding.get("evidence")) or bool(finding.get("request_evidence")) or bool(finding.get("response_evidence"))
    if status == "confirmed":
        return True
    if status == "suspected":
        return is_high_value_active_finding(finding) or (has_evidence and existence_rate >= 0.7)
    if status == "rejected":
        return has_evidence or bool(finding.get("audit_note")) or existence_rate >= 0.3
    return has_evidence or existence_rate >= 0.45


def _default_memory(challenge_code: str) -> Dict:
    return {
        "challenge_code": challenge_code,
        "display_url": "",
        "execution_url": "",
        "host": "unknown",
        "ports": [],
        "execution_attempts": 0,
        "counters": {
            "consecutive_failures": 0,
            "no_progress_rounds": 0,
            "no_action_rounds": 0,
            "advisor_loop_rounds": 0,
            "repeated_task_rounds": 0,
            "repeated_hypothesis_rounds": 0,
            "confirmed_count": 0,
            "suspected_count": 0,
        },
        "current_hypothesis_signature": "N/A",
        "candidate_surface_hints": [],
        "blocked_hypothesis_signatures": [],
        "last_execution_outcome": {},
        "findings": [],
        "frozen_findings": [],
        "strong_evidence_artifacts": [],
        "action_history": [],
        "errors": [],
        "updated_at": "",
    }


def _sanitize_memory_findings(items: List[Dict]) -> List[Dict]:
    sanitized_items: List[Dict] = []
    for item in list(items or []):
        if not isinstance(item, dict):
            continue
        cleaned = dict(item)
        cleaned["evidence"] = _sanitize_memory_snippet(cleaned.get("evidence") or "", finding=cleaned, max_chars=220)
        cleaned["request_evidence"] = [
            text
            for text in (
                _sanitize_memory_snippet(x, finding=cleaned, max_chars=220)
                for x in (cleaned.get("request_evidence") or [])
            )
            if text
        ][:6]
        cleaned["response_evidence"] = [
            text
            for text in (
                _sanitize_memory_snippet(x, finding=cleaned, max_chars=220)
                for x in (cleaned.get("response_evidence") or [])
            )
            if text
        ][:6]
        sanitized_items.append(cleaned)
    return sanitized_items


def _sanitize_loaded_memory(memory: Dict, challenge_code: str) -> Dict:
    cleaned = dict(memory or {})
    cleaned.setdefault("challenge_code", challenge_code)
    cleaned["findings"] = _sanitize_memory_findings(cleaned.get("findings") or [])
    cleaned["frozen_findings"] = _sanitize_memory_findings(cleaned.get("frozen_findings") or [])
    cleaned["strong_evidence_artifacts"] = _collect_strong_evidence_artifacts(cleaned.get("frozen_findings") or [])
    return cleaned


def _load_structured_memory(challenge_code: str) -> Dict:
    path = working_memory_json_path(challenge_code)
    if not path.exists():
        return _default_memory(challenge_code)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return _sanitize_loaded_memory(data, challenge_code)
    except Exception:
        pass
    return _default_memory(challenge_code)


def load_structured_working_memory(challenge_code: str) -> Dict:
    return _load_structured_memory(challenge_code)


def _merge_unique_strings(existing: List[str], incoming: List[str], limit: int) -> List[str]:
    result: List[str] = []
    seen = set()
    for item in list(existing or []) + list(incoming or []):
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result[-limit:]


def _memory_action_history(state: Dict) -> List[str]:
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
    return filtered[-18:]


def _state_findings_snapshot(state: Dict) -> List[Dict]:
    findings = []
    for item in list(state.get("findings") or [])[:12]:
        if not isinstance(item, dict):
            continue
        if not _is_memory_worthy_finding(item):
            continue
        findings.append(
            {
                "key": _finding_key(item),
                "status": str(item.get("status") or "unknown").lower(),
                "vuln_type": str(item.get("vuln_type") or "unknown"),
                "cve": str(item.get("cve") or "N/A"),
                "template_id": str(item.get("template_id") or "N/A"),
                "target": _finding_target(item),
                "strict_verified": bool(item.get("strict_verified", False)),
                "score": float(item.get("score") or item.get("confidence") or 0.0),
                "existence_rate": calibrated_finding_probability(item),
                "evidence": _finding_evidence_preview(item),
                "request_evidence": [
                    sanitized
                    for sanitized in (
                        _sanitize_memory_snippet(x, finding=item, max_chars=220)
                        for x in (item.get("request_evidence") or [])[:6]
                    )
                    if sanitized
                ],
                "response_evidence": [
                    sanitized
                    for sanitized in (
                        _sanitize_memory_snippet(x, finding=item, max_chars=220)
                        for x in (item.get("response_evidence") or [])[:6]
                    )
                    if sanitized
                ],
                "verification_checks": dict(item.get("verification_checks") or {}),
                "cve_verdict": str(item.get("cve_verdict") or "absent"),
                "audit_note": str(item.get("audit_note") or ""),
                "uncertainty_notes": [str(x) for x in (item.get("uncertainty_notes") or [])[:6]],
                "source_tool": str(item.get("source_tool") or "unknown"),
            }
        )
    return findings


def _merge_findings(existing: List[Dict], incoming: List[Dict]) -> List[Dict]:
    def _merge_checks(a: Dict, b: Dict) -> Dict:
        keys = set(dict(a or {}).keys()) | set(dict(b or {}).keys())
        merged_checks: Dict[str, bool] = {}
        for key in keys:
            merged_checks[key] = bool(dict(a or {}).get(key)) or bool(dict(b or {}).get(key))
        return merged_checks

    def _merge_item(base: Dict, extra: Dict) -> Dict:
        merged_item = dict(base or {})
        if not merged_item.get("evidence") and extra.get("evidence"):
            merged_item["evidence"] = extra.get("evidence")
        merged_item["strict_verified"] = bool(merged_item.get("strict_verified")) or bool(extra.get("strict_verified"))
        merged_item["verification_checks"] = _merge_checks(
            merged_item.get("verification_checks") or {},
            extra.get("verification_checks") or {},
        )
        merged_item["request_evidence"] = _merge_unique_strings(
            merged_item.get("request_evidence") or [],
            extra.get("request_evidence") or [],
            limit=8,
        )
        merged_item["response_evidence"] = _merge_unique_strings(
            merged_item.get("response_evidence") or [],
            extra.get("response_evidence") or [],
            limit=8,
        )
        merged_item["uncertainty_notes"] = _merge_unique_strings(
            merged_item.get("uncertainty_notes") or [],
            extra.get("uncertainty_notes") or [],
            limit=8,
        )
        merged_item["existence_rate"] = max(
            float(merged_item.get("existence_rate") or calibrated_finding_probability(merged_item) or 0.0),
            float(extra.get("existence_rate") or calibrated_finding_probability(extra) or 0.0),
        )
        merged_item["score"] = max(
            float(merged_item.get("score") or 0.0),
            float(extra.get("score") or 0.0),
        )
        if not merged_item.get("cve") and extra.get("cve"):
            merged_item["cve"] = extra.get("cve")
        if not merged_item.get("template_id") and extra.get("template_id"):
            merged_item["template_id"] = extra.get("template_id")
        if not merged_item.get("target") and extra.get("target"):
            merged_item["target"] = extra.get("target")
        current_cve_verdict = str(merged_item.get("cve_verdict") or "").strip().lower()
        extra_cve_verdict = str(extra.get("cve_verdict") or "").strip().lower()
        verdict_order = {"confirmed": 3, "weak_match": 2, "unverified": 1, "absent": 0, "": 0}
        if verdict_order.get(extra_cve_verdict, 0) > verdict_order.get(current_cve_verdict, 0):
            merged_item["cve_verdict"] = extra.get("cve_verdict")
        return merged_item

    def _rank(item: Dict) -> tuple:
        checks = dict(item.get("verification_checks") or {})
        order = {"confirmed": 0, "suspected": 1, "rejected": 2, "unknown": 9}
        return (
            order.get(str(item.get("status") or "unknown").lower(), 9),
            -1 if bool(item.get("strict_verified")) else 0,
            -1 if bool(checks.get("explicit_success_signal")) else 0,
            -1 if bool(checks.get("runtime_signal")) else 0,
            -float(item.get("existence_rate") or item.get("score") or 0.0),
        )

    merged: Dict[str, Dict] = {}
    for item in list(existing or []) + list(incoming or []):
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        if not key:
            continue
        current = merged.get(key)
        if not current:
            merged[key] = dict(item)
            continue
        if _rank(item) < _rank(current):
            merged[key] = _merge_item(dict(item), current)
        else:
            merged[key] = _merge_item(current, item)
    values = list(merged.values())
    values.sort(key=lambda x: ({"confirmed": 0, "suspected": 1, "rejected": 2}.get(str(x.get("status")).lower(), 9), -float(x.get("existence_rate") or x.get("score") or 0.0)))
    return values[:12]


def _is_frozen_finding(item: Dict) -> bool:
    status = str(item.get("status") or "unknown").strip().lower()
    if status not in {"suspected", "confirmed"}:
        return False
    if status == "confirmed":
        return has_strong_verification_signal(item) or is_high_value_active_finding(item)
    return is_high_value_active_finding(item)


def _frozen_rank(item: Dict) -> tuple:
    checks = dict(item.get("verification_checks") or {})
    return (
        1 if bool(item.get("strict_verified", False)) else 0,
        1 if bool(checks.get("explicit_success_signal")) else 0,
        1 if bool(checks.get("runtime_signal")) else 0,
        float(item.get("existence_rate") or item.get("score") or 0.0),
        len(item.get("response_evidence") or []),
        len(item.get("request_evidence") or []),
    )


def _merge_frozen_findings(existing: List[Dict], incoming: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}
    for item in list(existing or []) + [x for x in (incoming or []) if _is_frozen_finding(x)]:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        if not key:
            continue
        current = merged.get(key)
        if current is None or _frozen_rank(item) > _frozen_rank(current):
            merged[key] = dict(item)
            continue
        current["strict_verified"] = bool(current.get("strict_verified")) or bool(item.get("strict_verified"))
        current["request_evidence"] = _merge_unique_strings(current.get("request_evidence") or [], item.get("request_evidence") or [], limit=8)
        current["response_evidence"] = _merge_unique_strings(current.get("response_evidence") or [], item.get("response_evidence") or [], limit=8)
        current["uncertainty_notes"] = _merge_unique_strings(current.get("uncertainty_notes") or [], item.get("uncertainty_notes") or [], limit=8)
        if not current.get("evidence") and item.get("evidence"):
            current["evidence"] = item.get("evidence")
        merged[key] = current
    values = list(merged.values())
    values.sort(key=_frozen_rank, reverse=True)
    return values[:8]


def _collect_strong_evidence_artifacts(findings: List[Dict]) -> List[str]:
    artifacts: List[str] = []
    for item in findings or []:
        if not _is_frozen_finding(item):
            continue
        checks = dict(item.get("verification_checks") or {})
        if (
            str(item.get("status") or "").strip().lower() != "confirmed"
            and not bool(item.get("strict_verified"))
            and not bool(checks.get("runtime_signal"))
            and not bool(checks.get("explicit_success_signal"))
        ):
            continue
        header = (
            f"[{str(item.get('status') or 'unknown').lower()}] "
            f"{item.get('vuln_type', 'unknown')} | target={item.get('target', 'N/A')} | "
            f"cve={item.get('cve', 'N/A')}"
        )
        artifacts.append(header)
        evidence = _sanitize_memory_snippet(item.get("evidence") or "", finding=item, max_chars=260)
        if evidence:
            artifacts.append(evidence)
        for row in list(item.get("response_evidence") or [])[:4]:
            sanitized = _sanitize_memory_snippet(row, finding=item, max_chars=220)
            if sanitized:
                artifacts.append(sanitized)
        for row in list(item.get("request_evidence") or [])[:3]:
            sanitized = _sanitize_memory_snippet(row, finding=item, max_chars=220)
            if sanitized:
                artifacts.append(sanitized)
    return _merge_unique_strings([], artifacts, limit=18)


def _merge_structured_memory(existing: Dict, state: Dict, error: Optional[str] = None) -> Dict:
    challenge = state.get("current_challenge") or {}
    target_info = challenge.get("target_info") or {}
    detection_metrics = state.get("detection_metrics") or {}

    merged = dict(existing or {})
    merged["challenge_code"] = _challenge_code_from_state(state)
    merged["display_url"] = str(challenge.get("_target_url") or merged.get("display_url") or "")
    merged["execution_url"] = str(challenge.get("_execution_target_url") or merged.get("execution_url") or merged["display_url"])
    merged["host"] = str(target_info.get("ip") or merged.get("host") or "unknown")
    merged["ports"] = list(target_info.get("port") or merged.get("ports") or [])
    merged["current_hypothesis_signature"] = str(
        state.get("last_hypothesis_signature") or merged.get("current_hypothesis_signature") or "N/A"
    )
    merged["candidate_surface_hints"] = _merge_unique_strings(
        merged.get("candidate_surface_hints") or [],
        list(state.get("candidate_surface_hints") or []),
        limit=12,
    )
    merged["blocked_hypothesis_signatures"] = _merge_unique_strings(
        merged.get("blocked_hypothesis_signatures") or [],
        list(state.get("blocked_hypothesis_signatures") or []),
        limit=10,
    )
    latest_execution_outcome = _normalized_execution_outcome(state.get("last_execution_outcome"))
    if latest_execution_outcome:
        merged["last_execution_outcome"] = latest_execution_outcome
    else:
        merged["last_execution_outcome"] = _normalized_execution_outcome(merged.get("last_execution_outcome"))
    merged["execution_attempts"] = max(
        int(merged.get("execution_attempts", 0) or 0),
        int(state.get("execution_attempts", 0) or 0),
    )

    counters = dict(merged.get("counters") or {})
    counters["consecutive_failures"] = max(int(counters.get("consecutive_failures", 0) or 0), int(state.get("consecutive_failures", 0) or 0))
    counters["no_progress_rounds"] = max(int(counters.get("no_progress_rounds", 0) or 0), int(state.get("no_progress_rounds", 0) or 0))
    counters["no_action_rounds"] = max(int(counters.get("no_action_rounds", 0) or 0), int(state.get("no_action_rounds", 0) or 0))
    counters["advisor_loop_rounds"] = max(int(counters.get("advisor_loop_rounds", 0) or 0), int(state.get("advisor_loop_rounds", 0) or 0))
    counters["repeated_task_rounds"] = max(int(counters.get("repeated_task_rounds", 0) or 0), int(state.get("repeated_task_rounds", 0) or 0))
    counters["repeated_hypothesis_rounds"] = max(int(counters.get("repeated_hypothesis_rounds", 0) or 0), int(state.get("repeated_hypothesis_rounds", 0) or 0))
    counters["confirmed_count"] = max(int(counters.get("confirmed_count", 0) or 0), int(detection_metrics.get("confirmed_count", 0) or 0))
    counters["suspected_count"] = max(int(counters.get("suspected_count", 0) or 0), int(detection_metrics.get("suspected_count", 0) or 0))
    merged["counters"] = counters

    state_findings = _state_findings_snapshot(state)
    merged["findings"] = _merge_findings(merged.get("findings") or [], state_findings)
    merged["frozen_findings"] = _merge_frozen_findings(merged.get("frozen_findings") or [], state_findings)
    merged["strong_evidence_artifacts"] = _merge_unique_strings(
        merged.get("strong_evidence_artifacts") or [],
        _collect_strong_evidence_artifacts(merged.get("frozen_findings") or []),
        limit=24,
    )
    merged["action_history"] = _merge_unique_strings(
        merged.get("action_history") or [],
        _memory_action_history(state),
        limit=18,
    )
    if error:
        merged["errors"] = _merge_unique_strings(merged.get("errors") or [], [str(error)], limit=8)
    else:
        merged["errors"] = list(merged.get("errors") or [])
    merged["updated_at"] = datetime.now().isoformat(timespec="seconds")
    return merged


def build_working_memory_markdown(memory: Dict) -> str:
    counters = dict(memory.get("counters") or {})
    last_execution_outcome = dict(memory.get("last_execution_outcome") or {})
    findings = list(memory.get("findings") or [])
    frozen_findings = list(memory.get("frozen_findings") or [])
    strong_evidence_artifacts = list(memory.get("strong_evidence_artifacts") or [])
    action_history = list(memory.get("action_history") or [])
    errors = list(memory.get("errors") or [])

    lines: List[str] = [
        "# Intermediate Working Memory",
        "",
        f"- Last update: {memory.get('updated_at') or 'N/A'}",
        "",
        "## Target",
        f"- Challenge: {memory.get('challenge_code', 'unknown')}",
        f"- Display URL: {memory.get('display_url') or 'N/A'}",
        f"- Execution URL: {memory.get('execution_url') or 'N/A'}",
        f"- Host: {memory.get('host') or 'unknown'}",
        f"- Ports: {', '.join(str(x) for x in (memory.get('ports') or [])) or 'unknown'}",
        "",
        "## Status",
        f"- Execution attempts: {int(memory.get('execution_attempts', 0) or 0)}",
        f"- Consecutive failures: {int(counters.get('consecutive_failures', 0) or 0)}",
        f"- No-progress rounds: {int(counters.get('no_progress_rounds', 0) or 0)}",
        f"- No-action rounds: {int(counters.get('no_action_rounds', 0) or 0)}",
        f"- Advisor-loop rounds: {int(counters.get('advisor_loop_rounds', 0) or 0)}",
        f"- Repeated task rounds: {int(counters.get('repeated_task_rounds', 0) or 0)}",
        f"- Repeated hypothesis rounds: {int(counters.get('repeated_hypothesis_rounds', 0) or 0)}",
        f"- Current hypothesis signature: {memory.get('current_hypothesis_signature') or 'N/A'}",
        f"- Confirmed findings: {int(counters.get('confirmed_count', 0) or 0)}",
        f"- Suspected findings: {int(counters.get('suspected_count', 0) or 0)}",
        f"- Frozen findings: {len(frozen_findings)}",
    ]

    if last_execution_outcome:
        lines.extend(
            [
                f"- Last tool status: {last_execution_outcome.get('tool_status') or 'unknown'}",
                f"- Last verification status: {last_execution_outcome.get('verification_status') or 'unknown'}",
                f"- Last progress status: {last_execution_outcome.get('progress_status') or 'unknown'}",
            ]
        )
        if last_execution_outcome.get("summary"):
            lines.append(f"- Last execution summary: {last_execution_outcome.get('summary')}")
        if last_execution_outcome.get("should_retry_same_hypothesis"):
            lines.append("- Last routing hint: retry same hypothesis with stricter verification")

    candidate_surface_hints = list(memory.get("candidate_surface_hints") or [])
    if candidate_surface_hints:
        lines.extend(["", "## Candidate Surfaces"])
        for item in candidate_surface_hints[:10]:
            lines.append(f"- {item}")

    blocked_hypotheses = list(memory.get("blocked_hypothesis_signatures") or [])
    if blocked_hypotheses:
        lines.extend(["", "## Blocked Hypotheses"])
        for item in blocked_hypotheses[:8]:
            lines.append(f"- {item}")

    if frozen_findings:
        lines.extend(["", "## Frozen Findings"])
        for item in frozen_findings[:6]:
            line = (
                f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                f"strict_verified={bool(item.get('strict_verified', False))} | score={float(item.get('score') or 0.0):.3f}"
            )
            lines.append(line)
            checks = dict(item.get("verification_checks") or {})
            if checks:
                checks_text = ", ".join([f"{k}={bool(v)}" for k, v in checks.items()])
                lines.append(f"  checks: {checks_text}")
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                lines.append(f"  evidence: {evidence}")

    if findings:
        lines.extend(["", "## Findings"])
        for item in findings[:8]:
            line = (
                f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                f"template={item.get('template_id', 'N/A')} | strict_verified={bool(item.get('strict_verified', False))}"
            )
            lines.append(line)
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                lines.append(f"  evidence: {evidence}")

    if strong_evidence_artifacts:
        lines.extend(["", "## Strong Evidence Artifacts"])
        for item in strong_evidence_artifacts[:12]:
            lines.append(f"- {item}")

    if action_history:
        lines.extend(["", "## Recent Effective Actions"])
        for idx, action in enumerate(action_history[-8:], 1):
            lines.append(f"{idx}. {_truncate(str(action), 240)}")

    if errors:
        lines.extend(["", "## Errors"])
        for item in errors[-4:]:
            lines.append(f"- {_truncate(str(item), 220)}")

    lines.extend(
        [
            "",
            "## Rules",
            "- Frozen findings are higher-priority facts. Do not discard them unless a later deterministic check directly contradicts them.",
            "- If frozen findings exist, either confirm them more strictly or explain the contradiction. Do not silently pivot away.",
            "- Prefer these confirmed facts, failed paths, and current hypotheses instead of rereading all raw context.",
            "- If you continue with the same vulnerability family, provide a new endpoint, parameter, or differentiating runtime evidence.",
            "- Without stable runtime evidence, do not escalate directly to confirmed.",
            "",
        ]
    )
    return "\n".join(lines)


def persist_working_memory(state: Dict, error: Optional[str] = None) -> Optional[Path]:
    challenge_code = _challenge_code_from_state(state)
    if not challenge_code:
        return None
    merged = _merge_structured_memory(_load_structured_memory(challenge_code), state, error=error)
    json_path = working_memory_json_path(challenge_code)
    json_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path = working_memory_path(challenge_code)
    md_path.write_text(build_working_memory_markdown(merged), encoding="utf-8")
    return md_path


def _build_decision_memory_context(memory: Dict) -> str:
    memory = dict(memory or {})
    counters = dict(memory.get("counters") or {})
    outcome = dict(memory.get("last_execution_outcome") or {})
    frozen = list(memory.get("frozen_findings") or [])
    findings = list(memory.get("findings") or [])
    artifacts = list(memory.get("strong_evidence_artifacts") or [])
    actions = list(memory.get("action_history") or [])
    errors = list(memory.get("errors") or [])

    lines: List[str] = [
        "## Decision Memory",
        f"- Hypothesis signature: {memory.get('current_hypothesis_signature') or 'N/A'}",
        f"- Execution attempts: {int(memory.get('execution_attempts', 0) or 0)}",
        f"- Consecutive failures: {int(counters.get('consecutive_failures', 0) or 0)}",
        f"- No-progress rounds: {int(counters.get('no_progress_rounds', 0) or 0)}",
        f"- Repeated hypothesis rounds: {int(counters.get('repeated_hypothesis_rounds', 0) or 0)}",
    ]

    candidate_surface_hints = list(memory.get("candidate_surface_hints") or [])
    if candidate_surface_hints:
        lines.extend(["", "## Candidate Surfaces"])
        for item in candidate_surface_hints[:6]:
            lines.append(f"- {item}")

    blocked_hypotheses = list(memory.get("blocked_hypothesis_signatures") or [])
    if blocked_hypotheses:
        lines.extend(["", "## Blocked Hypotheses"])
        for item in blocked_hypotheses[:6]:
            lines.append(f"- {item}")

    if outcome:
        lines.extend(
            [
                "",
                "## Last Execution Outcome",
                f"- Tool status: {outcome.get('tool_status') or 'unknown'}",
                f"- Verification status: {outcome.get('verification_status') or 'unknown'}",
                f"- Progress status: {outcome.get('progress_status') or 'unknown'}",
            ]
        )
        if outcome.get("summary"):
            lines.append(f"- Summary: {outcome.get('summary')}")
        if outcome.get("should_retry_same_hypothesis"):
            lines.append("- Routing hint: retry the same hypothesis once with stricter PASS/FAIL evidence.")

    if frozen:
        lines.extend(["", "## Frozen Findings"])
        for item in frozen[:4]:
            lines.append(
                f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                f"strict_verified={bool(item.get('strict_verified', False))}"
            )
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                lines.append(f"  evidence: {_truncate(evidence, 180)}")

    unresolved = [
        item for item in findings
        if str(item.get("status") or "").strip().lower() in {"suspected", "rejected"}
    ]
    if unresolved:
        lines.extend(["", "## Unresolved Findings"])
        for item in unresolved[:4]:
            lines.append(
                f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                f"existence={float(item.get('existence_rate') or item.get('score') or 0.0):.3f}"
            )
            audit_note = str(item.get("audit_note") or "").strip()
            if audit_note:
                lines.append(f"  note: {_truncate(audit_note, 180)}")
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                lines.append(f"  evidence: {_truncate(evidence, 180)}")

    if artifacts:
        lines.extend(["", "## Strong Evidence Artifacts"])
        for row in artifacts[:6]:
            lines.append(f"- {_truncate(str(row), 160)}")

    if actions:
        lines.extend(["", "## Recent Effective Actions"])
        for item in actions[-5:]:
            lines.append(f"- {_truncate(str(item), 180)}")

    if errors:
        lines.extend(["", "## Recent Errors"])
        for item in errors[-3:]:
            lines.append(f"- {_truncate(str(item), 180)}")

    return "\n".join(lines)


def load_decision_memory_context(challenge_code: str, max_chars: int = 2200) -> str:
    memory = _load_structured_memory(challenge_code)
    text = _build_decision_memory_context(memory)
    return _truncate(text, max_chars) if text.strip() else ""


def load_decision_memory_for_state(state: Dict, max_chars: int = 2200) -> str:
    return load_decision_memory_context(_challenge_code_from_state(state), max_chars=max_chars)


def load_frozen_findings_context(challenge_code: str, max_chars: int = 2000) -> str:
    memory = _load_structured_memory(challenge_code)
    frozen = list(memory.get("frozen_findings") or [])
    all_findings = list(memory.get("findings") or [])
    lines: List[str] = []

    if frozen:
        lines.append("## Frozen Findings (High Priority)")
        for item in frozen[:5]:
            lines.append(
                f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                f"strict_verified={bool(item.get('strict_verified', False))} | score={float(item.get('score') or 0.0):.3f}"
            )
            checks = dict(item.get("verification_checks") or {})
            if checks:
                lines.append("  checks: " + ", ".join([f"{k}={bool(v)}" for k, v in checks.items()]))
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                lines.append("  evidence: " + _truncate(evidence, 220))

    if not frozen and all_findings:
        valuable_findings = [
            f for f in all_findings
            if (f.get("status") or "").lower() == "confirmed"
            or (
                (f.get("status") or "").lower() == "suspected"
                and float(f.get("existence_rate") or f.get("score") or 0.0) >= 0.4
            )
        ]
        if valuable_findings:
            lines.append("## Valuable Findings (Should Not Be Forgotten)")
            for item in valuable_findings[:5]:
                lines.append(
                    f"- [{item.get('status', 'unknown')}] {item.get('vuln_type', 'unknown')} | "
                    f"target={item.get('target', 'N/A')} | cve={item.get('cve', 'N/A')} | "
                    f"score={float(item.get('score') or item.get('existence_rate') or 0.0):.3f}"
                )
                evidence = str(item.get("evidence") or "").strip()
                if evidence:
                    lines.append("  evidence: " + _truncate(evidence, 180))

    artifacts = list(memory.get("strong_evidence_artifacts") or [])
    if artifacts:
        lines.append("")
        lines.append("## Strong Evidence Artifacts")
        for row in artifacts[:8]:
            lines.append(f"- {_truncate(str(row), 180)}")
    if not lines:
        return ""
    return _truncate("\n".join(lines), max_chars)


def load_frozen_findings_for_state(state: Dict, max_chars: int = 2000) -> str:
    return load_frozen_findings_context(_challenge_code_from_state(state), max_chars=max_chars)


def recover_findings_from_working_memory(challenge_code: str) -> List[Dict]:
    memory = _load_structured_memory(challenge_code)
    recovered: List[Dict] = []
    merged_items = _merge_findings(memory.get("findings") or [], memory.get("frozen_findings") or [])
    for item in list(merged_items or []):
        if not isinstance(item, dict):
            continue
        vuln_type = str(item.get("vuln_type") or "unknown").strip().lower()
        cve = str(item.get("cve") or "").strip().upper() or None
        target = str(item.get("target") or "").strip()
        recovered.append(
            {
                "vuln_name": f"{cve} ({vuln_type})" if cve else vuln_type,
                "vuln_type": vuln_type,
                "cve": cve,
                "template_id": str(item.get("template_id") or "").strip() or None,
                "status": str(item.get("status") or "suspected").strip().lower(),
                "strict_verified": bool(item.get("strict_verified", False)),
                "score": float(item.get("score") or 0.0),
                "existence_rate": float(item.get("existence_rate") or calibrated_finding_probability(item) or 0.0),
                "confidence": float(item.get("existence_rate") or item.get("score") or 0.0),
                "target_url": target,
                "endpoint": target,
                "evidence": str(item.get("evidence") or "").strip(),
                "source_tool": "working_memory_recovery",
                "cve_verdict": str(item.get("cve_verdict") or ("confirmed" if cve else "absent")).strip().lower(),
                "verification_checks": dict(item.get("verification_checks") or {}),
                "request_evidence": list(item.get("request_evidence") or []),
                "response_evidence": list(item.get("response_evidence") or []),
                "uncertainty_notes": list(item.get("uncertainty_notes") or []),
            }
        )
    return recovered
