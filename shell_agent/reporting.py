import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
import re
from urllib.parse import urlparse

from shell_agent.report_docx import convert_markdown_to_docx
from shell_agent.common import (
    calibrated_cve_probability,
    calibrated_finding_probability,
    count_actionable_findings,
    is_high_value_active_finding,
)


def _to_cn_vuln_type(vuln_type: str) -> str:
    mapping = {
        "rce": "远程代码执行",
        "ssti": "服务端模板注入",
        "sql_injection": "SQL注入",
        "xss": "跨站脚本攻击",
        "xxe": "XML外部实体注入",
        "ssrf": "服务端请求伪造",
        "file_inclusion": "文件包含/路径穿越",
        "auth_bypass": "认证/授权绕过",
        "unknown": "未知类型",
    }
    key = str(vuln_type or "").strip().lower()
    return mapping.get(key, vuln_type or "未知类型")


def _to_cn_source_tool(source_tool: str) -> str:
    mapping = {
        "execute_python_poc": "Python PoC执行器",
        "execute_command": "Kali命令执行器",
        "tool": "通用工具",
    }
    key = str(source_tool or "").strip().lower()
    return mapping.get(key, source_tool or "通用工具")


def _to_cn_cve_verdict(verdict: str) -> str:
    mapping = {
        "absent": "未归因",
        "invalid_format": "CVE格式无效",
        "unverified": "归因未验证",
        "weak_match": "弱匹配",
        "confirmed": "归因已确认",
    }
    key = str(verdict or "").strip().lower()
    return mapping.get(key, verdict or "未归因")


def _translate_note_to_cn(text: str) -> str:
    note = str(text or "")
    replacements = [
        ("Downgraded in reporting stage: strict verification checks were not satisfied.", "报告阶段降级：未满足严格验证条件。"),
        ("Finding downgraded to suspected because CVE attribution is uncertain.", "漏洞降级为疑似：CVE归因不确定。"),
        ("Finding downgraded to suspected because strict verification checks were not fully satisfied.", "漏洞降级为疑似：严格验证检查未全部通过。"),
        ("Finding downgraded to suspected because output is status-code-only.", "漏洞降级为疑似：证据仅有状态码变化。"),
        ("Finding downgraded to suspected due to negative signals without runtime success.", "漏洞降级为疑似：存在负向信号且无运行时成功证据。"),
        ("Adaptive recheck: not reproduced in second pass, downgraded to rejected.", "自适应复检：二次复检未复现，已降级为拒绝。"),
        ("Adaptive recheck: at least one pass rejected this finding.", "自适应复检：至少一轮已拒绝该发现。"),
        ("Adaptive recheck: retained by intersection of first and second pass.", "自适应复检：通过首轮与二轮交集保留。"),
        ("Intersection passed but strict confirmed criteria not met in both passes.", "交集通过但两轮均未满足严格确认标准。"),
        ("CVE attribution lacks runtime verification evidence and cannot be marked as confirmed.", "CVE归因缺乏运行时验证证据，不能标记为已确认。"),
        ("CVE attribution is inferred from signature matching and requires stronger confirmation evidence.", "CVE归因来自签名推断，仍需更强证据确认。"),
        ("Signature-inferred CVE lacks critical exploit tokens in evidence.", "签名推断的CVE缺少关键利用特征。"),
        ("Signature-inferred CVE lacks runtime verification evidence in current output.", "签名推断的CVE在当前输出中缺少运行时验证证据。"),
        ("CVE sibling conflict resolved", "同类CVE冲突已收敛"),
        ("Generic finding suppressed: overlaps with specific confirmed finding", "泛化漏洞已抑制：与已确认的具体漏洞证据高度重合"),
        ("CVE attribution downgraded because vulnerability type is not strictly confirmed yet.", "CVE归因已降级：漏洞类型尚未通过严格确认。"),
    ]
    for src, dst in replacements:
        note = note.replace(src, dst)
    return note


def _localize_line_to_cn(text: str) -> str:
    line = str(text or "")
    replacements = [
        ("Confirm the target service is reachable and record the target URL/port.", "确认目标服务可达并记录目标 URL/端口。"),
        ("Send a minimal probe request based on the suspected vulnerability type.", "根据疑似漏洞类型发送最小化探测请求。"),
        ("Compare request/response behavior and confirm reproducible vulnerability characteristics.", "对比请求/响应行为，确认漏洞特征可复现。"),
        ("Preserve request/response evidence for audit and replay.", "保留请求与响应证据，便于审计与复测。"),
        ("Send a controlled command-execution probe to the target.", "向目标发送可控命令执行探测。"),
        ("Confirm command execution using deterministic output (e.g., uid/whoami).", "通过确定性输出（如 uid/whoami）确认命令执行。"),
        ("Build verification requests aligned with", "按照"),
        ("public exploit conditions.", "公开利用条件构造验证请求。"),
        ("Key request evidence:", "关键请求证据："),
    ]
    for src, dst in replacements:
        line = line.replace(src, dst)
    return line


def _strip_cve_from_vuln_name(vuln_name: str) -> str:
    name = str(vuln_name or "").strip()
    if not name:
        return ""
    name = re.sub(r"\bCVE-\d{4}-\d{4,7}\b", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[（(]\s*[)）]", "", name)
    name = name.strip(" -_:：()（）[]")
    name = re.sub(r"\s{2,}", " ", name).strip()
    return name


def _localize_vuln_name(vuln_name: str, vuln_type: str, cve: str) -> str:
    if cve:
        return f"{cve}（{_to_cn_vuln_type(vuln_type)}）"
    cleaned = _strip_cve_from_vuln_name(vuln_name)
    lower = cleaned.lower()
    mapping = {
        "remote code execution (rce)": "远程代码执行（RCE）",
        "server-side template injection (ssti)": "服务端模板注入（SSTI）",
        "sql injection": "SQL注入",
        "cross-site scripting (xss)": "跨站脚本攻击（XSS）",
        "xml external entity (xxe)": "XML外部实体注入（XXE）",
        "file inclusion / path traversal": "文件包含/路径穿越",
        "server-side request forgery (ssrf)": "服务端请求伪造（SSRF）",
        "authentication/authorization bypass": "认证/授权绕过",
        "potential vulnerability": "潜在漏洞",
    }
    return mapping.get(lower, cleaned or _to_cn_vuln_type(vuln_type) or "未命名漏洞")


def _to_cn_objective_mode(mode: str) -> str:
    m = str(mode or "").strip().lower()
    mapping = {
        "hybrid": "混合模式（漏洞检测优先）",
        "detect": "检测模式",
        "flag": "Flag模式",
    }
    return mapping.get(m, mode or "未知模式")


def _repair_mojibake(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    suspicious_markers = (
        "闁", "鏉", "锟", "鈿", "馃", chr(0xFFFD),
        "鎻", "寤", "鍙", "鍏", "鏈", "绔", "澶", "鍘", "妫", "娴", "婕", "鎴",
    )
    if not any(m in text for m in suspicious_markers):
        return text

    candidates: List[str] = [text]
    for enc, dec in (("latin1", "utf-8"), ("gb18030", "utf-8"), ("gbk", "utf-8")):
        try:
            candidates.append(text.encode(enc, errors="strict").decode(dec, errors="strict"))
        except Exception:
            continue

    def bad_score(s: str) -> tuple[int, int]:
        return (sum(s.count(m) for m in suspicious_markers), s.count(chr(0xFFFD)))

    return min(candidates, key=bad_score)


def _normalize_text(value: Any) -> Any:
    if isinstance(value, str):
        return _repair_mojibake(value)
    if isinstance(value, list):
        return [_normalize_text(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize_text(v) for k, v in value.items()}
    return value


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _reports_dir() -> Path:
    report_dir = _project_root() / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def _safe_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(value))
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe.strip("_") or "report"


def _truncate(value: str, max_len: int) -> str:
    value = str(value)
    return value if len(value) <= max_len else value[:max_len]


def _finding_probability(finding: Dict) -> float:
    return calibrated_finding_probability(finding)


def _finding_cve_probability(finding: Dict, type_probability: float) -> float:
    return calibrated_cve_probability(finding, type_probability=type_probability)


def _normalize_cve_id(cve: Any) -> str:
    text = str(cve or "").strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", text):
        return text
    return ""


def _normalize_cve_rankings(finding: Dict, type_probability: float) -> List[Dict]:
    rows = []
    seen = set()
    for item in list(finding.get("cve_rankings") or []):
        if not isinstance(item, dict):
            continue
        cve = _normalize_cve_id(item.get("cve"))
        if not cve or cve in seen:
            continue
        prob = float(item.get("probability", 0.0) or 0.0)
        if prob <= 0.0:
            continue
        seen.add(cve)
        rows.append(
            {
                "cve": cve,
                "probability": max(0.0, min(1.0, prob)),
                "source": str(item.get("source") or ""),
                "vector_consistent": bool(item.get("vector_consistent", False)),
            }
        )

    if not rows:
        cve = _normalize_cve_id(finding.get("cve"))
        fallback_prob = _finding_cve_probability(finding, type_probability)
        if cve and fallback_prob > 0:
            rows = [{"cve": cve, "probability": fallback_prob, "source": "fallback", "vector_consistent": False}]

    rows.sort(key=lambda x: float(x.get("probability", 0.0) or 0.0), reverse=True)
    rows = rows[:8]
    total = sum(float(x.get("probability", 0.0) or 0.0) for x in rows) or 1.0
    normalized = []
    for idx, row in enumerate(rows, 1):
        normalized.append(
            {
                "rank": idx,
                "cve": row["cve"],
                "probability": round(float(row.get("probability", 0.0) or 0.0) / total, 4),
                "source": row.get("source") or "",
                "vector_consistent": bool(row.get("vector_consistent", False)),
            }
        )
    return normalized


def _is_noise_line(line: str) -> bool:
    lower = (line or "").strip().lower()
    if not lower:
        return True
    noise = ["status code", "response header", "header:", "<!doctype html", "<html"]
    return any(n in lower for n in noise)


def _pick_key_evidence(finding: Dict) -> str:
    high_priority = [
        "uid=",
        "root:x:",
        "54289",
        "hello 49",
        "exploit success",
        "vulnerable: true",
        '"vulnerable": true',
        "ognl",
        "cve-",
    ]
    medium_priority = ["response", "request", "payload", "whoami", "struts2", "template", "sql"]

    candidates: List[str] = []
    candidates.extend([str(x) for x in (finding.get("response_evidence") or [])])
    candidates.extend([str(x) for x in (finding.get("request_evidence") or [])])

    evidence_text = str(finding.get("evidence") or "")
    if evidence_text:
        candidates.extend([ln.strip() for ln in evidence_text.splitlines() if ln.strip()][:200])

    for line in candidates:
        lower = line.lower()
        if any(k in lower for k in high_priority):
            return line[:260]

    for line in candidates:
        lower = line.lower()
        if _is_noise_line(lower):
            continue
        if any(k in lower for k in medium_priority):
            return line[:260]

    for line in candidates:
        if not _is_noise_line(line):
            return line[:260]

    return ""


def _verification_text(finding: Dict) -> str:
    status = (finding.get("status") or "").strip().lower()
    if status == "confirmed" and bool(finding.get("strict_verified")):
        return "已验证"
    probability = _finding_probability(finding) * 100
    return f"未完成严格验证（当前存在度估计约 {probability:.1f}%）"


def _extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"https?://[^\s'\"`<>]+", str(text), flags=re.IGNORECASE)


def _normalize_endpoint_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw.rstrip("/")

    if not parsed.scheme or not parsed.netloc:
        return raw.rstrip("/")

    path = parsed.path or "/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return normalized.rstrip("/") if path != "/" else normalized


def _normalize_endpoint_identity(endpoint: str, fallback_target: str = "") -> str:
    raw = _normalize_endpoint_url(endpoint or fallback_target)
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
    except Exception:
        return raw.lower()

    if not parsed.scheme or not parsed.netloc:
        return raw.lower()

    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{path}{query}".lower()


def _rewrite_endpoint_for_display(endpoint: str, display_target: str = "", execution_target: str = "") -> str:
    normalized = _normalize_endpoint_url(endpoint)
    if not normalized:
        return normalized
    if not display_target or not execution_target:
        return normalized

    try:
        endpoint_parsed = urlparse(normalized)
        display_parsed = urlparse(_normalize_endpoint_url(display_target))
        execution_parsed = urlparse(_normalize_endpoint_url(execution_target))
    except Exception:
        return normalized

    if not endpoint_parsed.scheme or not endpoint_parsed.netloc:
        return normalized
    if not display_parsed.scheme or not display_parsed.netloc:
        return normalized
    if not execution_parsed.scheme or not execution_parsed.netloc:
        return normalized
    if endpoint_parsed.netloc.lower() != execution_parsed.netloc.lower():
        return normalized

    rewritten = f"{display_parsed.scheme.lower()}://{display_parsed.netloc}{endpoint_parsed.path or '/'}"
    if endpoint_parsed.query:
        rewritten = f"{rewritten}?{endpoint_parsed.query}"
    return rewritten.rstrip("/") if (endpoint_parsed.path or "/") != "/" else rewritten


def _extract_target_endpoint(finding: Dict, fallback_target: str = "", execution_target: str = "") -> str:
    candidates: List[str] = []
    for item in (finding.get("request_evidence") or []):
        candidates.extend(_extract_urls_from_text(str(item)))
    for item in (finding.get("response_evidence") or []):
        candidates.extend(_extract_urls_from_text(str(item)))
    candidates.extend(_extract_urls_from_text(str(finding.get("evidence") or "")))

    for candidate in candidates:
        normalized = _normalize_endpoint_url(candidate)
        if normalized:
            return _rewrite_endpoint_for_display(normalized, fallback_target, execution_target)
    return _normalize_endpoint_url(fallback_target)


def _finding_rank(finding: Dict) -> tuple:
    return (
        1 if _is_verified_finding(finding) else 0,
        1 if _is_high_value_suspected_finding(finding) else 0,
        float(finding.get("existence_rate", 0.0) or 0.0),
        float(finding.get("confidence", 0.0) or 0.0),
        len(finding.get("request_evidence") or []),
        len(finding.get("response_evidence") or []),
    )


def _normalize_finding(finding: Dict, fallback_target: str = "", execution_target: str = "") -> Dict:
    finding = _normalize_text(dict(finding))
    cve_raw = _normalize_cve_id(finding.get("cve"))
    strict_verified = bool(finding.get("strict_verified", False))
    status = str(finding.get("status", "suspected")).strip().lower()
    cve_verdict = str(finding.get("cve_verdict", "absent")).strip().lower()
    cve_confirmed = bool(cve_raw) and strict_verified and status == "confirmed" and cve_verdict == "confirmed"
    cve = cve_raw if cve_confirmed else ""
    uncertainty_notes = [_translate_note_to_cn(x) for x in list(finding.get("uncertainty_notes", []) or [])]
    if status == "confirmed" and not strict_verified:
        status = "suspected"
        uncertainty_notes.append(
            "报告阶段降级：未满足严格验证条件。"
        )
    if cve_raw and not cve_confirmed:
        note = "报告阶段不展示未严格确认的主CVE，仅保留候选概率列表。"
        if note not in uncertainty_notes:
            uncertainty_notes.append(note)

    remediation = [_localize_line_to_cn(x) for x in list(finding.get("remediation") or [])]
    if cve and not remediation:
        remediation = [
            f"核查 {cve} 受影响版本并升级到官方修复版本。",
            "修复后执行回归安全测试，确认漏洞不可复现。",
        ]

    reproduction_steps = [_localize_line_to_cn(x) for x in list(finding.get("reproduction_steps") or [])]

    normalized = {
        "vuln_name": _localize_vuln_name(finding.get("vuln_name", "未命名漏洞"), finding.get("vuln_type", "unknown"), cve),
        "vuln_type": _to_cn_vuln_type(finding.get("vuln_type", "unknown")),
        "cve": cve,
        "cve_verdict": finding.get("cve_verdict", "absent"),
        "cve_verdict_text": _to_cn_cve_verdict(finding.get("cve_verdict", "absent")),
        "cve_confidence": finding.get("cve_confidence", 0.0),
        "uncertainty_notes": uncertainty_notes,
        "status": status,
        "workflow_score": finding.get("workflow_score", finding.get("score")),
        "score": finding.get("score"),
        "score_breakdown": finding.get("score_breakdown", {}),
        "template_id": finding.get("template_id"),
        "confidence": finding.get("confidence", 0.0),
        "source_tool": _to_cn_source_tool(finding.get("source_tool", "tool")),
        "intel_tags": finding.get("intel_tags", {}),
        "request_evidence": finding.get("request_evidence", []),
        "response_evidence": finding.get("response_evidence", []),
        "reproduction_steps": reproduction_steps,
        "key_evidence": "",
        "remediation": remediation,
        "evidence": finding.get("evidence", ""),
        "timestamp": finding.get("timestamp"),
        "strict_verified": strict_verified,
        "verification_checks": finding.get("verification_checks", {}),
        "cve_rankings": finding.get("cve_rankings", []),
        "target_endpoint": _extract_target_endpoint(finding, fallback_target, execution_target),
        "execution_endpoint": _extract_target_endpoint(finding, execution_target or fallback_target, execution_target),
        "target_endpoint_identity": "",
    }

    normalized["key_evidence"] = _pick_key_evidence(normalized)
    normalized["verification_text"] = _verification_text(normalized)
    type_probability = round(_finding_probability(normalized), 4)
    normalized["type_probability"] = type_probability
    normalized["existence_rate"] = type_probability
    rankings = _normalize_cve_rankings(normalized, type_probability)
    if rankings and not (status == "confirmed" and strict_verified):
        for row in rankings:
            row["probability"] = round(float(row.get("probability", 0.0) or 0.0) * type_probability, 4)
    normalized["cve_rankings"] = rankings

    cve_prob = _finding_cve_probability(normalized, type_probability)
    cve_id = _normalize_cve_id(normalized.get("cve"))
    if rankings:
        if cve_id:
            for row in rankings:
                if row.get("cve") == cve_id:
                    cve_prob = float(row.get("probability", cve_prob) or cve_prob)
                    break
        else:
            cve_prob = float(rankings[0].get("probability", cve_prob) or cve_prob)
    normalized["cve_probability"] = round(max(0.0, min(1.0, cve_prob)), 4)
    normalized["target_endpoint_identity"] = _normalize_endpoint_identity(
        normalized.get("target_endpoint", ""), fallback_target
    )
    return normalized


def _derive_target(challenge: Dict) -> str:
    target_info = challenge.get("target_info", {}) if challenge else {}
    target = challenge.get("_target_url") if challenge else None
    if target:
        return target
    ip = target_info.get("ip", "")
    ports = target_info.get("port", [])
    port = ports[0] if ports else ""
    return f"http://{ip}:{port}" if ip else "unknown"


def _primary_vuln_name(findings: List[Dict]) -> str:
    if not findings:
        return "未发现明确漏洞"
    confirmed = [f for f in findings if (f.get("status") or "").lower() == "confirmed"]
    if confirmed:
        return confirmed[0].get("vuln_name") or "已验证漏洞"
    suspected_type = findings[0].get("vuln_type")
    return suspected_type or findings[0].get("vuln_name") or "疑似漏洞"


def _is_verified_finding(finding: Dict) -> bool:
    return (finding.get("status") or "").strip().lower() == "confirmed" and bool(finding.get("strict_verified"))


def _is_high_value_suspected_finding(finding: Dict) -> bool:
    return (finding.get("status") or "").strip().lower() == "suspected" and is_high_value_active_finding(finding)


def _report_finding_dedup_key(finding: Dict) -> str:
    vuln_type = str(finding.get("vuln_type") or "").strip().lower()
    endpoint = str(finding.get("target_endpoint_identity") or "").strip().lower()
    cve = _normalize_cve_id(finding.get("cve"))
    cve_confirmed = (
        str(finding.get("cve_verdict") or "").strip().lower() == "confirmed"
        and _is_verified_finding(finding)
    )
    if cve and cve_confirmed:
        return f"endpoint:{endpoint}|cve:{cve}|type:{vuln_type}"
    return f"endpoint:{endpoint}|type:{vuln_type}"


def _select_report_findings(findings: List[Dict]) -> List[Dict]:
    """
    Reporting rule:
    1) Verified findings first.
    2) Unverified findings are included only if existence_rate > 50%.
    3) Unverified findings appear after verified findings.
    """
    candidates = [
        f
        for f in findings
        if _is_verified_finding(f)
        or _is_high_value_suspected_finding(f)
        or float(f.get("existence_rate", 0.0) or 0.0) > 0.5
    ]
    deduped: Dict[str, Dict] = {}
    for item in candidates:
        key = _report_finding_dedup_key(item)
        current = deduped.get(key)
        if current is None or _finding_rank(item) > _finding_rank(current):
            deduped[key] = item

    selected = list(deduped.values())
    selected.sort(key=_finding_rank, reverse=True)
    return selected


def build_report_payload(challenge: Dict, result: Dict) -> Dict:
    challenge = _normalize_text(dict(challenge or {}))
    result = _normalize_text(dict(result or {}))
    target = _derive_target(challenge)
    execution_target = str(challenge.get("_execution_target_url") or target or "")
    all_findings = [_normalize_finding(f, target, execution_target) for f in (result.get("findings") or [])]
    findings = _select_report_findings(all_findings)
    runtime_detection_metrics = dict(result.get("detection_metrics", {}) or {})
    runtime_total = int(runtime_detection_metrics.get("total_findings", len(all_findings)) or 0)
    actionable_counts = count_actionable_findings(all_findings)
    runtime_confirmed = int(
        runtime_detection_metrics.get(
            "confirmed_count",
            actionable_counts.get("confirmed", 0),
        )
        or 0
    )
    runtime_suspected = int(
        runtime_detection_metrics.get(
            "suspected_count",
            actionable_counts.get("suspected", 0),
        )
        or 0
    )
    runtime_rejected = int(
        runtime_detection_metrics.get(
            "rejected_count",
            len([f for f in all_findings if (f.get("status") or "").lower() == "rejected"]),
        )
        or 0
    )
    runtime_strict_verified = int(
        runtime_detection_metrics.get(
            "strict_verified_count",
            len([f for f in all_findings if _is_verified_finding(f)]),
        )
        or 0
    )
    runtime_fpr = float(
        runtime_detection_metrics.get(
            "false_positive_rate",
            round((runtime_rejected / runtime_total) if runtime_total else 0.0, 4),
        )
        or 0.0
    )

    summary = {
        "success": bool(result.get("success")),
        "objective_mode": result.get("objective_mode", "hybrid"),
        "vulnerability_detected": bool(result.get("vulnerability_detected")),
        "findings_count": runtime_total,
        "display_findings_count": len(findings),
        "verified_findings_count": runtime_confirmed,
        "suspected_findings_count": runtime_suspected,
        "rejected_findings_count": runtime_rejected,
        "strict_verified_findings_count": runtime_strict_verified,
        "verification_status": "已验证" if runtime_confirmed > 0 else "未验证",
        "flag_found": bool(result.get("flag")),
        "attempts": result.get("attempts", 0),
        "elapsed_time": result.get("elapsed_time", 0),
    }

    detection_metrics = dict(runtime_detection_metrics)
    detection_metrics.setdefault("total_findings", runtime_total)
    detection_metrics.setdefault("confirmed_count", runtime_confirmed)
    detection_metrics.setdefault("suspected_count", runtime_suspected)
    detection_metrics.setdefault("rejected_count", runtime_rejected)
    detection_metrics.setdefault("false_positive_rate", round(runtime_fpr, 4))
    detection_metrics.setdefault("strict_verified_count", runtime_strict_verified)
    detection_metrics.setdefault(
        "uncertain_cve_count",
        len(
            [
                f
                for f in all_findings
                if (
                    f.get("cve") and f.get("cve_verdict") in {"invalid_format", "unverified", "weak_match"}
                )
                or ((f.get("status") or "").lower() != "confirmed" and (f.get("cve_rankings") or []))
            ]
        ),
    )

    return {
        "report_meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "challenge_code": challenge.get("challenge_code", "unknown") if challenge else "unknown",
            "target": target,
            "execution_target": execution_target,
            "difficulty": challenge.get("difficulty", "unknown") if challenge else "unknown",
            "primary_vuln_name": _primary_vuln_name(findings),
        },
        "summary": summary,
        "detection_metrics": detection_metrics,
        "agent_metrics": result.get("agent_metrics", {}) or {},
        "findings": findings,
        "flag": result.get("flag"),
        "error": result.get("error"),
    }


def _render_markdown(report: Dict) -> str:
    meta = report["report_meta"]
    summary = report["summary"]
    detection_metrics = report.get("detection_metrics", {})
    agent_metrics = report.get("agent_metrics", {})
    findings = report["findings"]

    lines: List[str] = []
    lines.append("# 渗透测试报告")
    lines.append("")
    lines.append("## 一、基本信息")
    lines.append(f"- 生成时间: `{meta['generated_at']}`")
    lines.append(f"- 任务ID: `{meta['challenge_code']}`")
    lines.append(f"- 目标地址: `{meta['target']}`")
    if meta.get("execution_target") and meta.get("execution_target") != meta.get("target"):
        lines.append(f"- 执行地址: `{meta['execution_target']}`")
    lines.append(f"- 难度: `{meta['difficulty']}`")
    lines.append("")

    lines.append("## 二、总体结论")
    lines.append(f"- 执行结果: `{'成功' if summary['success'] else '未完成'}`")
    lines.append(f"- 运行模式: `{_to_cn_objective_mode(summary['objective_mode'])}`")
    lines.append(f"- 是否确认漏洞: `{'是' if summary['vulnerability_detected'] else '否'}`")
    lines.append(f"- 是否发现可疑或确认漏洞: `{'是' if summary['findings_count'] > 0 else '否'}`")
    lines.append(f"- 漏洞总数: `{summary['findings_count']}`")
    if summary.get("display_findings_count", summary["findings_count"]) != summary["findings_count"]:
        lines.append(f"- 报告展示漏洞数: `{summary.get('display_findings_count', 0)}`")
    lines.append(f"- 已验证漏洞数: `{summary['verified_findings_count']}`")
    lines.append(f"- 严格验证通过数: `{summary['strict_verified_findings_count']}`")
    lines.append(f"- 总体验证状态: `{summary['verification_status']}`")
    lines.append(f"- 尝试次数: `{summary['attempts']}`")
    lines.append(f"- 总耗时(秒): `{summary['elapsed_time']}`")
    if report.get("flag"):
        lines.append(f"- Flag值: `{report.get('flag')}`")
    else:
        lines.append("- Flag值: `未发现（不影响漏洞检测结论）`")
    lines.append("")

    lines.append("## 三、检测指标")
    lines.append(f"- 已确认数量: `{detection_metrics.get('confirmed_count', 0)}`")
    lines.append(f"- 疑似数量: `{detection_metrics.get('suspected_count', 0)}`")
    lines.append(f"- 已排除数量: `{detection_metrics.get('rejected_count', 0)}`")
    lines.append(f"- 误报率: `{detection_metrics.get('false_positive_rate', 0.0)}`")
    lines.append(f"- 平均检测时长(秒): `{detection_metrics.get('avg_detection_time_seconds', summary.get('elapsed_time', 0))}`")
    lines.append(f"- CVE归因不确定数量: `{detection_metrics.get('uncertain_cve_count', 0)}`")
    lines.append(f"- 严格验证通过数量: `{detection_metrics.get('strict_verified_count', 0)}`")
    family_dist = detection_metrics.get("cve_family_distribution", {}) or {}
    if family_dist:
        dist_text = ", ".join([f"{k}: {v}" for k, v in family_dist.items()])
        lines.append(f"- CVE族分布: `{dist_text}`")
    else:
        lines.append("- CVE族分布: `无`")
    lines.append("")

    lines.append("## 四、协作运行统计")
    lines.append(f"- 顾问智能体回合数: `{agent_metrics.get('advisor_rounds', 0)}`")
    lines.append(f"- 主控智能体回合数: `{agent_metrics.get('main_rounds', 0)}`")
    lines.append(f"- PoC执行智能体回合数: `{agent_metrics.get('poc_rounds', 0)}`")
    lines.append(f"- 命令执行智能体回合数: `{agent_metrics.get('docker_rounds', 0)}`")
    lines.append(f"- 工具节点回合数: `{agent_metrics.get('tool_rounds', 0)}`")
    lines.append("")

    lines.append("## 五、漏洞明细")
    if not findings:
        if int(detection_metrics.get("rejected_count", 0) or 0) > 0:
            lines.append("- 未展示高价值结构化漏洞发现；运行期仅产生了被拒绝或低价值发现。")
        else:
            lines.append("- 未生成结构化漏洞发现。")
    else:
        for idx, finding in enumerate(findings, 1):
            vuln_type = finding.get("vuln_type", "未知类型")
            type_prob = float(finding.get("type_probability", finding.get("existence_rate", 0.0)) or 0.0)
            type_confirmed = bool(finding.get("strict_verified")) and (finding.get("status") or "").lower() == "confirmed"
            type_verdict_text = "已确认" if type_confirmed else f"疑似（存在度估计 {type_prob * 100:.1f}%）"

            lines.append(f"### 5.{idx} {vuln_type}")
            lines.append(f"- 漏洞类型: `{vuln_type}`")
            lines.append(f"- 具体目标地址: `{finding.get('target_endpoint') or meta['target']}`")
            if finding.get("execution_endpoint") and finding.get("execution_endpoint") != finding.get("target_endpoint"):
                lines.append(f"- 实际执行地址: `{finding.get('execution_endpoint')}`")
            lines.append(f"- 类型结论: `{type_verdict_text}`")
            if finding.get("vuln_name") and finding.get("vuln_name") != vuln_type:
                lines.append(f"- 漏洞名称（模型输出）: `{finding['vuln_name']}`")
            lines.append(f"- 验证状态: `{finding['verification_text']}`")
            lines.append(f"- 严格验证: `{'通过' if finding.get('strict_verified') else '未通过'}`")
            lines.append(f"- 存在度估计: `{type_prob * 100:.1f}%`")
            lines.append(f"- 证据置信度: `{finding.get('confidence', 0.0)}`")
            lines.append(f"- 工作流评分: `{finding.get('workflow_score', finding.get('score', '无'))}`")
            score_breakdown = finding.get("score_breakdown") or {}
            if score_breakdown:
                lines.append(f"- 评分拆解: `{json.dumps(score_breakdown, ensure_ascii=False)}`")
            lines.append(f"- 模板ID: `{finding.get('template_id') or '无'}`")
            lines.append(f"- 证据来源工具: `{finding['source_tool']}`")
            if finding.get("key_evidence"):
                lines.append(f"- 关键验证证据: `{finding.get('key_evidence')}`")

            cve_id = str(finding.get("cve") or "").strip()
            cve_verdict = str(finding.get("cve_verdict") or "").strip().lower()
            cve_prob = float(finding.get("cve_probability", 0.0) or 0.0)
            cve_rankings = list(finding.get("cve_rankings") or [])
            cve_confirmed = (
                cve_verdict == "confirmed"
                and bool(finding.get("strict_verified"))
                and (finding.get("status") or "").lower() == "confirmed"
            )
            if cve_confirmed and cve_id:
                lines.append(f"- 对应CVE: `已确认 {cve_id}`")
            else:
                ranking_text = "; ".join(
                    [f"{row.get('cve')}（{float(row.get('probability', 0.0) or 0.0) * 100:.1f}%）" for row in cve_rankings]
                )
                if ranking_text:
                    lines.append(f"- 可能CVE（按概率）: `{ranking_text}`")
                elif cve_id and cve_prob > 0:
                    lines.append(f"- 可能CVE（按概率）: `{cve_id}（{cve_prob * 100:.1f}%）`")

            checks = finding.get("verification_checks") or {}
            if checks:
                lines.append(f"- 验证检查项: `{json.dumps(checks, ensure_ascii=False)}`")

            notes = finding.get("uncertainty_notes") or []
            for note in notes:
                lines.append(f"- 不确定性说明: `{note}`")

            lines.append("- 请求证据:")
            req = finding.get("request_evidence") or []
            if req:
                for item in req:
                    lines.append(f"- {item}")
            else:
                lines.append("- 未提取到明确请求证据。")

            lines.append("- 响应证据:")
            resp = finding.get("response_evidence") or []
            if resp:
                for item in resp:
                    lines.append(f"- {item}")
            else:
                lines.append("- 未提取到明确响应证据。")

            lines.append("- 复现步骤:")
            steps = finding.get("reproduction_steps") or []
            if steps:
                for s_idx, step in enumerate(steps, 1):
                    lines.append(f"{s_idx}. {step}")
            else:
                lines.append("1. 未生成复现步骤。")

            lines.append("- 修复建议:")
            remediations = finding.get("remediation") or []
            if remediations:
                for item in remediations:
                    lines.append(f"- {item}")
            else:
                lines.append("- 未生成修复建议。")
            lines.append("")

    if report.get("error"):
        lines.append("## 六、错误信息")
        lines.append(f"- `{report['error']}`")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def save_report_files(challenge: Dict, result: Dict) -> str:
    report = build_report_payload(challenge, result)
    report_dir = _reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    target_part = _truncate(_safe_name(report["report_meta"]["target"]), 80)
    vuln_part = _truncate(_safe_name(report["report_meta"]["primary_vuln_name"]), 60)
    verified_part = "已验证" if report["summary"].get("verified_findings_count", 0) > 0 else "未验证"
    base_name = f"{timestamp}-{target_part}-{vuln_part}-{verified_part}"

    md_path = report_dir / f"{base_name}.md"
    docx_path = report_dir / f"{base_name}.docx"

    # Use UTF-8 BOM on Windows to avoid editor mis-detection and mojibake.
    md_path.write_text(_render_markdown(report), encoding="utf-8-sig")
    convert_markdown_to_docx(md_path, docx_path)
    return str(md_path)
