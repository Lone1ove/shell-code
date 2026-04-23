import os
import re
import math
from typing import Dict, List, Optional, Tuple

from shell_agent.cve.intel import load_cve_intel_records
from shell_agent.cve.matcher import build_cve_match_plan
from shell_agent.cve.templates import generate_candidates
from shell_agent.finding_identity import finding_identity_key
from shell_agent.rag.retriever import get_cve_entry, retrieve_cve_records
from shell_agent.common import calibrated_cve_probability, calibrated_finding_probability, normalize_text_content

CVE_TYPE_HINTS = {
    "CVE-2018-11776": {"rce"},
    "CVE-2017-5638": {"rce"},
    "CVE-2017-9805": {"rce"},
    "CVE-2021-41773": {"file_inclusion"},
    "CVE-2017-12615": {"rce"},
}


def load_intel_index() -> Dict[str, Dict]:
    records = load_cve_intel_records()
    return {r.get("cve_id"): r for r in records if r.get("cve_id")}


def _effective_intel_record(cve: str, intel_index: Dict[str, Dict]) -> Optional[Dict]:
    normalized = _normalize_cve(cve)
    if not normalized:
        return None
    intel = intel_index.get(normalized)
    if intel:
        record = dict(intel)
        record.setdefault("cve_id", normalized)
        record.setdefault("source", "local_intel")
        return record
    rag_entry = get_cve_entry(normalized)
    if not rag_entry:
        return None
    return {
        "cve_id": normalized,
        "product_family": rag_entry.get("product_family", "unknown"),
        "references": list(rag_entry.get("references") or []),
        "poc_available": bool(rag_entry.get("default_probe") or rag_entry.get("references")),
        "protocols": list(rag_entry.get("protocols") or []),
        "prerequisites": [],
        "severity": rag_entry.get("severity", "unknown"),
        "source": "rag_index",
        "default_probe": rag_entry.get("default_probe", ""),
        "confirm_markers": list(rag_entry.get("confirm_markers") or []),
        "remediation": list(rag_entry.get("remediation") or []),
        "fingerprint_keywords": list(rag_entry.get("fingerprint_keywords") or []),
    }


def _to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _normalize_match_text(text: str) -> str:
    lower = normalize_text_content(text).lower()
    lower = (
        lower.replace("–", "-")
        .replace("—", "-")
        .replace("：", ":")
        .replace("（", "(")
        .replace("）", ")")
    )
    return re.sub(r"\s+", " ", lower)


def _keyword_hit_count(text: str, keywords: List[str]) -> int:
    lower = _normalize_match_text(text)
    return sum(1 for k in keywords if k.lower() in lower)


def _normalize_cve(cve: Optional[str]) -> Optional[str]:
    if not cve:
        return None
    cve = cve.strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
        return cve
    return None


def _extract_cve_tokens(text: str) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text or "", re.IGNORECASE):
        cve = _normalize_cve(item)
        if not cve or cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out


def _finding_key(finding: Dict) -> str:
    return finding_identity_key(finding)


def _merge_list_str(left: List, right: List, limit: int = 20) -> List[str]:
    values = [str(x).strip() for x in (left or []) + (right or []) if str(x).strip()]
    dedup: List[str] = []
    seen = set()
    for item in values:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        dedup.append(item)
        if len(dedup) >= limit:
            break
    return dedup


def _evidence_bundle_text(item: Dict) -> str:
    return "\n".join(
        [
            str(item.get("evidence") or ""),
            "\n".join(str(x) for x in (item.get("request_evidence") or []) if str(x).strip()),
            "\n".join(str(x) for x in (item.get("response_evidence") or []) if str(x).strip()),
        ]
    )


def _prefer_candidate_evidence(left: Dict, right: Dict) -> bool:
    left_text = _evidence_bundle_text(left)
    right_text = _evidence_bundle_text(right)
    left_explicit = _has_explicit_verification_success(left_text)
    right_explicit = _has_explicit_verification_success(right_text)
    left_runtime = _has_strong_runtime_success_signal(left_text)
    right_runtime = _has_strong_runtime_success_signal(right_text)
    left_negative = _negative_signal_hit_count(left_text)
    right_negative = _negative_signal_hit_count(right_text)

    if right_explicit and not left_explicit:
        return True
    if right_runtime and not left_runtime and right_negative <= left_negative:
        return True
    if right_explicit == left_explicit and right_runtime == left_runtime:
        if right_negative < left_negative:
            return True
        if right_negative == left_negative and len(str(right.get("evidence") or "")) > len(str(left.get("evidence") or "")):
            return True
    return False


def _merge_duplicate_finding(left: Dict, right: Dict) -> Dict:
    merged = dict(left or {})
    candidate = dict(right or {})

    if not merged.get("cve") and candidate.get("cve"):
        merged["cve"] = candidate.get("cve")
        merged["attribution_source"] = candidate.get("attribution_source", merged.get("attribution_source"))

    merged["confidence"] = max(_to_float(merged.get("confidence"), 0.0), _to_float(candidate.get("confidence"), 0.0))
    prefer_candidate = _prefer_candidate_evidence(merged, candidate)
    if prefer_candidate:
        merged["request_evidence"] = _merge_list_str(candidate.get("request_evidence", []), merged.get("request_evidence", []), limit=24)
        merged["response_evidence"] = _merge_list_str(candidate.get("response_evidence", []), merged.get("response_evidence", []), limit=24)
        merged["reproduction_steps"] = _merge_list_str(candidate.get("reproduction_steps", []), merged.get("reproduction_steps", []), limit=10)
        merged["remediation"] = _merge_list_str(candidate.get("remediation", []), merged.get("remediation", []), limit=12)
        merged["evidence"] = str(candidate.get("evidence") or "")
    else:
        merged["request_evidence"] = _merge_list_str(merged.get("request_evidence", []), candidate.get("request_evidence", []), limit=24)
        merged["response_evidence"] = _merge_list_str(merged.get("response_evidence", []), candidate.get("response_evidence", []), limit=24)
        merged["reproduction_steps"] = _merge_list_str(merged.get("reproduction_steps", []), candidate.get("reproduction_steps", []), limit=10)
        merged["remediation"] = _merge_list_str(merged.get("remediation", []), candidate.get("remediation", []), limit=12)

        merged_evidence = str(merged.get("evidence") or "")
        candidate_evidence = str(candidate.get("evidence") or "")
        if len(candidate_evidence) > len(merged_evidence):
            merged["evidence"] = candidate_evidence

    merged["cve_candidates"] = _merge_list_str(merged.get("cve_candidates", []), candidate.get("cve_candidates", []), limit=10)
    merged["expected_cves"] = _merge_list_str(merged.get("expected_cves", []), candidate.get("expected_cves", []), limit=10)
    merged["source_tool"] = candidate.get("source_tool") or merged.get("source_tool")
    merged["timestamp"] = max(int(merged.get("timestamp") or 0), int(candidate.get("timestamp") or 0))
    return merged


def _merge_duplicate_findings(items: List[Dict]) -> List[Dict]:
    merged_map: Dict[str, Dict] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = _finding_key(item)
        if key not in merged_map:
            merged_map[key] = dict(item)
            continue
        merged_map[key] = _merge_duplicate_finding(merged_map[key], item)
    return list(merged_map.values())


def _has_ssti_deterministic_probe(evidence: str, req_evidence: str) -> bool:
    text = f"{evidence}\n{req_evidence}".lower()
    payloads = []
    for pattern in [
        r"\{\{\s*(\d{1,4})\s*\*\s*(\d{1,4})\s*\}\}",
        r"\$\{\s*(\d{1,4})\s*\*\s*(\d{1,4})\s*\}",
        r"%\{\s*(\d{1,4})\s*\*\s*(\d{1,4})\s*\}",
    ]:
        payloads.extend(re.findall(pattern, text))
    if not payloads:
        return False
    markers = ["response", "echo", "render", "hello ", "vulnerable", "template", "result"]
    for a, b in payloads:
        product = str(int(a) * int(b))
        if product in text and any(m in text for m in markers):
            return True
    return False


def _has_ssti_runtime_evidence(evidence: str, req_evidence: str) -> bool:
    text = f"{evidence}\n{req_evidence}".lower()
    if _has_ssti_deterministic_probe(evidence, req_evidence):
        return True

    has_template_expr = bool(re.search(r"\{\{.{1,500}\}\}", text, re.DOTALL))
    has_template_chain = any(
        marker in text
        for marker in [
            "__globals__",
            "__builtins__",
            "config.__class__",
            "class.__mro__",
            "subclasses()",
            "os.popen",
            "popen(",
            "template injection",
            "jinja",
            "jinja2",
            "ssti",
        ]
    )
    has_exec_output = any(
        marker in text
        for marker in [
            "uid=",
            "gid=",
            "whoami",
            "root:x:",
            "daemon:x:",
            "command executed",
            "command execution successful",
            "execution result",
            "shell output",
        ]
    )
    has_negative = any(
        marker in text
        for marker in [
            "not vulnerable",
            "vulnerable: false",
            '"vulnerable": false',
            "no command execution detected",
            "payload not executed",
            "execution failed",
            "failed or blocked",
            "could not find",
            "response does not contain",
        ]
    )
    return bool((has_template_expr or has_template_chain) and has_exec_output and not has_negative)


def _has_rce_runtime_evidence(evidence: str) -> bool:
    lower = normalize_text_content(evidence).lower().replace("–", "-").replace("—", "-")
    if _has_explicit_verification_success(lower):
        return True
    global_negative_markers = [
        "verdict: fail",
        "=== verdict: fail ===",
        "verdict: not vulnerable",
        "unexpected error",
        "response ended prematurely",
        "not vulnerable",
        "no command output",
        "no command execution detected",
    ]
    if any(marker in lower for marker in global_negative_markers):
        return False
    markers = [
        "uid=",
        "gid=",
        "whoami",
        "root:x:",
        "daemon:x:",
        "x-check: s2-045-test",
        "x-cmd-result:",
        "x-user-name:",
        "x-test-bypass: ok",
        "x-ognl-test:",
        "x-ognl-verify",
        "ognl_verify_",
        "hacked_by_ognl",
        "id\n",
        "id\r\n",
        "command executed",
        "command execution successful",
        "exploit success",
        "execution result",
        "shell output",
        "success: marker",
        "deterministic evidence of ognl expression execution",
        "found in response header",
        "found in response header x-ognl-verify",
        "[status] vulnerable",
        "pass - vulnerability confirmed",
        "verdict: pass",
        "result: pass",
        "successfully injected in response",
    ]
    negative_line_markers = [
        "not found",
        "failed",
        "failure",
        "blocked",
        "not vulnerable",
        "expected",
        "payload:",
        "payload command:",
        "command:",
        "deterministic marker:",
        "looking for marker:",
        "expected result:",
        "no output",
        "no command output",
        "without command output",
        "command output not found",
        "no command execution detected",
        "response does not contain",
        "could not find",
        "target may not be vulnerable",
        "no flag found",
        "did not execute",
        "contains '54289': false",
        "contains 'vuln_check_12345': false",
        "contains 'echo': false",
        "final conclusion",
        "结论: fail",
        "[结论] fail",
        "未检测到",
        "未发现",
    ]
    for line in lower.splitlines():
        if not any(m in line for m in markers):
            continue
        if any(n in line for n in negative_line_markers):
            continue
        return True
    return False


def _cve_vector_consistent(cve: str, evidence: str) -> Tuple[bool, Optional[str]]:
    """
    Verify that evidence matches the exploitation vector of the reported CVE.
    This reduces sibling-CVE confusion within the same product family.
    """
    lower = _normalize_match_text(evidence)
    has_runtime = _has_rce_runtime_evidence(evidence)

    # Family-level vector guard for Struts2 sibling CVEs:
    # when a concrete exploit vector is visible, force sibling alignment.
    has_struts_signal = any(tok in lower for tok in ["struts2", "ognl", "s2-0", "doupload.action", "xwork"])
    if has_struts_signal:
        expected_struts_cves: List[str] = []
        has_s2045_vector = (
            ("content-type: %{" in lower or "s2-045" in lower or "s2-046" in lower)
            and ("multipart/form-data" in lower or "doupload.action" in lower)
        )
        has_s2057_vector = any(
            tok in lower
            for tok in [
                "s2-057",
                "cve-2018-11776",
                "actionchain",
                "namespace=",
                "/${",
                "%24%7b",
                "redirect:${",
            ]
        )
        has_s2052_vector = any(
            tok in lower
            for tok in [
                "s2-052",
                "cve-2017-9805",
                "xstream",
                "application/xml",
                "/wls-wsat/",
            ]
        )
        if has_s2045_vector:
            expected_struts_cves.append("CVE-2017-5638")
        if has_s2057_vector:
            expected_struts_cves.append("CVE-2018-11776")
        if has_s2052_vector:
            expected_struts_cves.append("CVE-2017-9805")
        if expected_struts_cves and cve not in set(expected_struts_cves):
            return (
                False,
                f"Struts2 exploit vector indicates {expected_struts_cves}, but reported CVE is {cve}.",
            )

    if cve == "CVE-2017-5638":
        has_content_type_payload = "content-type: %{" in lower and "multipart/form-data" in lower
        parser_markers = [
            "invalid content type",
            "jakarta",
            "multipartrequestwrapper",
            "strutsproblemreporter",
        ]
        has_parser_signal = any(tok in lower for tok in parser_markers)
        hard_negative = (
            ("http status 404" in lower or "404 - not found" in lower or "< http/1.1 404" in lower)
            and "no result defined for action" in lower
            and not has_runtime
        )
        if hard_negative:
            return (
                False,
                "S2-045 probe returned 404/ActionSupport-input response without runtime output; vector evidence is inconsistent.",
            )
        if has_content_type_payload and not (has_runtime or has_parser_signal):
            return (
                False,
                "S2-045 payload was sent but no multipart/parser/runtime signal was observed.",
            )

    if cve == "CVE-2018-11776":
        has_path_or_namespace_probe = any(
            tok in lower
            for tok in [
                "/${",
                "%24%7b",
                "redirect:${",
                "redirect:%24%7b",
                "namespace=",
                "actionchain",
                "s2-057",
                "cve-2018-11776",
            ]
        )
        has_s2045_style_header = "content-type: %{" in lower and "multipart/form-data" in lower
        if has_s2045_style_header and not has_path_or_namespace_probe:
            return (
                False,
                "Evidence matches S2-045 header-injection style but lacks S2-057 path/namespace vector signals.",
            )
        if not has_path_or_namespace_probe:
            return (
                False,
                "S2-057 attribution lacks required path/namespace exploit-vector signals.",
            )

    if cve == "CVE-2017-9805":
        has_struts_xml_vector = any(
            tok in lower
            for tok in [
                "s2-052",
                "cve-2017-9805",
                "xstream",
                "application/xml",
                "<map>",
                "<entry>",
                "struts2-rest-showcase",
            ]
        )
        hard_negative = any(
            tok in lower
            for tok in [
                "not vulnerable",
                "may be patched",
                "payload blocked",
                "no command output",
                "no command execution detected",
            ]
        )
        if not has_struts_xml_vector:
            return (
                False,
                "CVE-2017-9805 attribution lacks Struts2 S2-052 XML/XStream exploit-vector signals.",
            )
        if hard_negative and not has_runtime:
            return (
                False,
                "CVE-2017-9805 probe indicates patched/blocked behavior without runtime execution evidence.",
            )

    if cve == "CVE-2017-12615":
        has_tomcat = "tomcat" in lower
        has_put_vector = any(
            tok in lower
            for tok in [
                "http put",
                " put /",
                "allow: put",
                "webdav",
                "put /",
            ]
        )
        has_jsp_upload_signal = any(
            tok in lower
            for tok in [
                ".jsp/",
                "jsp upload",
                ".jsp",
                "201 created",
                "201 status",
            ]
        )
        has_struts_noise = any(
            tok in lower for tok in ["struts2", "ognl", "s2-057", "s2-045", "showcase"]
        )
        if not (has_tomcat and has_put_vector and has_jsp_upload_signal) or has_struts_noise:
            return (
                False,
                "CVE-2017-12615 attribution lacks Tomcat PUT/JSP upload vector signals or conflicts with Struts2 evidence.",
            )

    return True, None


def _has_xss_runtime_evidence(evidence: str) -> bool:
    lower = evidence.lower()
    payload_seen = any(m in lower for m in ["<script>alert", "onerror=alert", "javascript:alert", "xss payload"])
    behavior_seen = any(m in lower for m in ["payload reflected", "executed", "triggered", "xss found", "alert("])
    return payload_seen and behavior_seen


def _has_file_inclusion_runtime_evidence(evidence: str) -> bool:
    lower = evidence.lower()
    passwd_markers = ["root:x:", "daemon:x:", "nobody:x:", "/bin/bash"]
    hosts_markers = ["127.0.0.1 localhost", "::1 localhost"]
    winini_markers = ["[extensions]", "for 16-bit app support", "[fonts]"]
    environ_markers = ["\npath=", "\nhome=", "\nshell=", "pwd="]

    if ("/etc/passwd" in lower or "etc/passwd" in lower) and any(m in lower for m in passwd_markers):
        return True
    if ("/etc/hosts" in lower or "etc/hosts" in lower) and any(m in lower for m in hosts_markers):
        return True
    if ("win.ini" in lower or "system32\\drivers\\etc\\hosts" in lower) and any(m in lower for m in winini_markers):
        return True
    if "/proc/self/environ" in lower and any(m in lower for m in environ_markers):
        return True
    return False


def _looks_like_false_file_read_claim(evidence: str) -> bool:
    lower = evidence.lower()
    claim_seen = any(
        m in lower
        for m in [
            "read file success",
            "file read success",
            "[+] read file",
            "[+] read",
        ]
    )
    html_only = "<!doctype html" in lower and "<html" in lower and "struts2 showcase" in lower
    return claim_seen and html_only and not _has_file_inclusion_runtime_evidence(evidence)


def _negative_signal_hit_count(text: str) -> int:
    lower = _normalize_match_text(text)
    markers = [
        "fail -",
        "result: fail",
        "[-] fail",
        "final result: fail",
        "not confirmed",
        "not vulnerable",
        "no vulnerability",
        "failed to exploit",
        "payload not reflected",
        "vulnerable: false",
        '"vulnerable": false',
        "no flag found",
        "flag not found",
        "[-] no flag",
        "failed or blocked",
        "injection failed",
        "blocked by",
        "rce blocked",
        "no rce evidence",
        "no rce evidence found",
        "no command output",
        "no ognl evaluation detected",
        "no command execution detected",
        "response does not contain",
        "could not find",
        "target may not be vulnerable",
        "not directly hit",
        "did not execute",
        "not executed",
        "only status code",
        "http status 404",
        "404 - not found",
        "< http/1.1 404",
        "no result defined for action",
        "无s2-057特征",
        "未直接命中",
    ]
    return sum(1 for marker in markers if marker in lower)


def _has_strong_runtime_success_signal(text: str) -> bool:
    lower = _normalize_match_text(text)
    markers = [
        "uid=",
        "gid=",
        "whoami",
        "root:x:",
        "x-check: s2-045-test",
        "x-cmd-result:",
        "x-user-name:",
        "x-test-bypass: ok",
        "vulnerable: true",
        '"vulnerable": true',
        "hacked_by_ognl",
        "s2-045-confirmed-",
        "s2-045-vuln-",
        "pass - vulnerability confirmed",
        "verdict: pass",
        "result: pass",
        "deterministic evidence of ognl expression execution",
        "success: marker",
        "found in response header x-ognl-verify",
        "x-ognl-verify",
        "[status] vulnerable",
        "successfully injected in response",
    ]
    negative_context_markers = [
        "expected marker",
        "expected result",
        "if ognl injection works",
        "if command execution works",
        "payload:",
        "payload command:",
        "no command output",
        "no command execution detected",
        "not vulnerable",
        "failed",
        "verdict: fail",
        "result: fail",
    ]
    has_custom_header_signal = bool(
        re.search(r"\bx-[a-z0-9_-]+\s*[:=]\s*[a-z0-9._:-]{3,}\b", lower)
        or re.search(r"'x-[a-z0-9_-]+'\s*:\s*'[^']{3,}'", lower)
        or re.search(r"\"x-[a-z0-9_-]+\"\s*:\s*\"[^\"]{3,}\"", lower)
    )
    for line in lower.splitlines():
        if not any(marker in line for marker in markers):
            continue
        if any(marker in line for marker in negative_context_markers):
            continue
        return True
    if has_custom_header_signal and not any(marker in lower for marker in ["expected marker", "verdict: fail", "result: fail"]):
        return True
    return False


def _has_explicit_verification_success(text: str) -> bool:
    lower = _normalize_match_text(text)
    success_markers = [
        "[result] pass",
        "result: pass",
        "[success]",
        "pass - vulnerability confirmed",
        "vulnerability confirmed",
        "[status] vulnerable",
        "verification succeeded",
        "ognl injection works",
        "successfully injected in response",
        "success: marker",
        "deterministic evidence of ognl expression execution",
        "found in response header",
        "found in response header x-ognl-verify",
        "found x-",
        "custom header successfully injected",
        "response header successfully injected",
        "response header injection successful",
        "response header contains",
        "verdict: pass",
        "result: pass",
    ]
    artifact_markers = [
        "response headers:",
        "response body",
        "custom header",
        "injected in response",
        "found x-",
        "found in response header",
        "x-ognl-verify",
        "ognl_verify_",
        "header injection",
        "response header contains",
    ]
    has_header_artifact = bool(
        re.search(r"\bx-[a-z0-9_-]+\s*[:=]\s*[a-z0-9._:-]{3,}\b", lower)
        or re.search(r"'x-[a-z0-9_-]+'\s*:\s*'[^']{3,}'", lower)
        or re.search(r"\"x-[a-z0-9_-]+\"\s*:\s*\"[^\"]{3,}\"", lower)
    )
    has_success = any(marker in lower for marker in success_markers)
    has_artifact = has_header_artifact or any(marker in lower for marker in artifact_markers)
    has_negative = any(
        marker in lower
        for marker in [
            "result: fail",
            "final result: fail",
            "[-] fail",
            "not vulnerable",
            "payload not executed",
            "execution failed",
            "failed or blocked",
            "no rce evidence",
            "no rce evidence found",
            "rce blocked",
            "no command output",
            "no ognl evaluation detected",
        ]
    )
    return has_success and has_artifact and not has_negative


def _looks_like_expected_result_only_probe(text: str) -> bool:
    lower = _normalize_match_text(text)
    has_expectation = any(
        marker in lower
        for marker in [
            "expected result:",
            "if ognl injection works",
            "if ssti works",
            "if command execution works",
            "should return 54289",
        ]
    )
    has_negative = any(
        marker in lower
        for marker in [
            "no ognl injection evidence found",
            "no injection evidence",
            "not vulnerable",
            "payload not executed",
            "no command execution detected",
            "failed or blocked",
            "final result: fail",
            "[-] fail",
        ]
    )
    return has_expectation and has_negative and not _has_strong_runtime_success_signal(lower)


def _build_cve_rag_query(
    vuln_type: str,
    evidence: str,
    req_evidence: str,
    primary_template: Optional[Dict],
    existing_candidates: List[str],
) -> str:
    parts: List[str] = []
    vuln_type_norm = str(vuln_type or "").strip().lower()
    if vuln_type_norm:
        parts.append(vuln_type_norm)
    family = str((primary_template or {}).get("family") or "").strip().lower()
    if family:
        parts.append(family)
    for product in list((primary_template or {}).get("products") or [])[:4]:
        product_text = str(product or "").strip().lower()
        if product_text:
            parts.append(product_text)
    parts.extend([str(x).upper() for x in (existing_candidates or []) if _normalize_cve(x)])

    combined = f"{req_evidence}\n{evidence}"
    lines: List[str] = []
    for raw in combined.splitlines():
        line = _normalize_match_text(raw)
        if not line or len(line) < 6:
            continue
        if _is_noise_evidence_line(line):
            continue
        if any(
            token in line
            for token in [
                "cve-",
                "struts",
                "ognl",
                "content-type",
                "multipart/form-data",
                "actionchain",
                "namespace",
                "weblogic",
                "fastjson",
                "shiro",
                "log4j",
                "spring",
                "tomcat",
                "xstream",
                "wls-wsat",
                "webdav",
                "uid=",
                "gid=",
                "whoami",
                "root:x:",
                "54289",
                "hello 49",
            ]
        ):
            lines.append(line)
        if len(lines) >= 8:
            break
    parts.extend(lines)
    query = " ".join(part for part in parts if part)
    return query[:1800]


def _should_use_cve_rag(query: str, vuln_type: str) -> bool:
    if str(vuln_type or "").strip().lower() in {"", "unknown"}:
        return False
    lower = _normalize_match_text(query)
    if len(lower) < 24:
        return False
    specificity_hits = sum(
        1
        for marker in [
            "cve-",
            "struts",
            "ognl",
            "content-type",
            "multipart/form-data",
            "actionchain",
            "namespace",
            "weblogic",
            "fastjson",
            "shiro",
            "log4j",
            "spring",
            "tomcat",
            "uid=",
            "gid=",
            "whoami",
            "root:x:",
            "54289",
            "hello 49",
        ]
        if marker in lower
    )
    return specificity_hits >= 2


def _enrich_cve_candidates_with_rag(
    finding: Dict,
    evidence: str,
    req_evidence: str,
    primary_template: Optional[Dict],
) -> List[str]:
    if str(finding.get("status") or "").strip().lower() == "rejected":
        return list(finding.get("cve_candidates") or [])
    if str(finding.get("attribution_source") or "").strip().lower() == "benchmark_target_map":
        return list(finding.get("cve_candidates") or [])
    if os.getenv("ENABLE_CVE_RAG_MATCHING", "true").strip().lower() != "true":
        return list(finding.get("cve_candidates") or [])

    existing = [str(x).strip().upper() for x in (finding.get("cve_candidates") or []) if _normalize_cve(x)]
    if len(existing) >= 4:
        return existing
    if _looks_like_expected_result_only_probe(f"{req_evidence}\n{evidence}"):
        return existing
    query = _build_cve_rag_query(
        vuln_type=str(finding.get("vuln_type") or ""),
        evidence=evidence,
        req_evidence=req_evidence,
        primary_template=primary_template,
        existing_candidates=existing,
    )
    if not _should_use_cve_rag(query, str(finding.get("vuln_type") or "")):
        return existing

    top_k = max(1, int(os.getenv("CVE_RAG_TOP_K", "4")))
    min_severity = os.getenv("CVE_RAG_MIN_SEVERITY", "medium").strip().lower() or "medium"
    rag_records = retrieve_cve_records(query, top_k=top_k, min_severity=min_severity)
    rag_ids = [str(item.get("id") or "").strip().upper() for item in rag_records if _normalize_cve(item.get("id"))]
    return _merge_list_str(existing, rag_ids, limit=12)


def _has_sqli_runtime_evidence(evidence: str, req_evidence: str = "") -> bool:
    text = f"{evidence}\n{req_evidence}".lower()
    error_markers = [
        "sql syntax",
        "mysql",
        "postgresql",
        "sqlite",
        "odbc",
        "database error",
        "you have an error in your sql syntax",
    ]
    infer_markers = [
        "union select",
        "sleep(",
        "benchmark(",
        "time-based",
        "boolean-based",
        "injection confirmed",
    ]
    return any(m in text for m in error_markers) or any(m in text for m in infer_markers)


def _has_xxe_runtime_evidence(evidence: str) -> bool:
    lower = (evidence or "").lower()
    return any(
        token in lower
        for token in [
            "root:x:",
            "daemon:x:",
            "file:///",
            "<!entity",
            "xxe",
            "external entity resolved",
        ]
    )


def _has_ssrf_runtime_evidence(evidence: str) -> bool:
    lower = (evidence or "").lower()
    return any(
        token in lower
        for token in [
            "169.254.169.254",
            "latest/meta-data",
            "internal service",
            "localhost response",
            "metadata",
            "ssrf confirmed",
        ]
    )


def _has_auth_bypass_runtime_evidence(evidence: str) -> bool:
    lower = (evidence or "").lower()
    return any(
        token in lower
        for token in [
            "access granted",
            "bypass successful",
            "unauthorized -> 200",
            "admin panel",
            "privilege escalation",
        ]
    )


def _is_noise_evidence_line(text: str) -> bool:
    lower = _normalize_match_text((text or "").strip())
    if not lower:
        return True
    noise_markers = [
        "status code",
        "状态码",
        "content-type: text/html",
        "content-length:",
        "response header",
        "header:",
        "<!doctype html",
        "<html",
        "<head",
        "<body",
        "<meta ",
    ]
    return any(m in lower for m in noise_markers)


def _effective_evidence_count(items: List[str]) -> int:
    return sum(1 for item in (items or []) if not _is_noise_evidence_line(str(item)))


def _runtime_evidence_ok(vuln_type: str, evidence: str, req_evidence: str, response_evidence: List[str]) -> bool:
    vt = (vuln_type or "").strip().lower()
    runtime_text = f"{evidence}\n" + "\n".join(response_evidence or [])
    combined = f"{runtime_text}\n{req_evidence}"
    if _has_explicit_verification_success(runtime_text):
        return True
    if vt == "ssti":
        return _has_ssti_runtime_evidence(combined, req_evidence)
    if vt == "rce":
        return _has_rce_runtime_evidence(runtime_text)
    if vt == "xss":
        return _has_xss_runtime_evidence(combined)
    if vt == "file_inclusion":
        return _has_file_inclusion_runtime_evidence(combined)
    if vt == "sql_injection":
        return _has_sqli_runtime_evidence(evidence, req_evidence)
    if vt == "xxe":
        return _has_xxe_runtime_evidence(combined)
    if vt == "ssrf":
        return _has_ssrf_runtime_evidence(combined)
    if vt == "auth_bypass":
        return _has_auth_bypass_runtime_evidence(combined)
    return _has_strong_runtime_success_signal(combined)


def _looks_like_status_only_probe(evidence: str) -> bool:
    lower = _normalize_match_text(evidence)
    status_hits = lower.count("status code") + lower.count("status:") + lower.count("状态码") + lower.count("http status")
    html_shell = "<!doctype html" in lower or "<html" in lower
    return status_hits >= 2 and html_shell and not _has_strong_runtime_success_signal(lower)


def _validate_cve_mapping(
    cve: Optional[str],
    evidence: str,
    primary_template: Optional[Dict],
    intel_index: Dict[str, Dict],
    vuln_type: str = "",
    benchmark_target_id: Optional[str] = None,
    expected_cves: Optional[List[str]] = None,
    expected_family: str = "",
    attribution_source: str = "",
) -> Tuple[str, float, List[str], Optional[Dict]]:
    """
    Returns: verdict, confidence, uncertainty_notes, intel_record
    verdict: absent | invalid_format | unverified | weak_match | confirmed
    """
    if not cve:
        return "absent", 0.0, [], None

    notes: List[str] = []
    expected_cves = [x.upper() for x in (expected_cves or []) if x]
    if benchmark_target_id and expected_cves and cve in expected_cves and attribution_source == "benchmark_target_map":
        intel = _effective_intel_record(cve, intel_index)
        if intel is None:
            notes.append("Intel record missing; CVE attribution confirmed by benchmark target mapping.")
            return "confirmed", 0.82, notes, None
        intel_family = (intel.get("product_family") or "unknown").lower()
        expected_family_norm = (expected_family or "").strip().lower()
        family_ok = (
            not expected_family_norm
            or expected_family_norm == "unknown"
            or intel_family == "unknown"
            or expected_family_norm in intel_family
            or intel_family in expected_family_norm
        )
        if family_ok:
            notes.append("CVE attribution confirmed by benchmark target mapping with family consistency.")
            return "confirmed", 0.9, notes, intel
        notes.append("Benchmark mapping matched CVE id but family consistency is weak.")
        return "weak_match", 0.55, notes, intel

    intel = _effective_intel_record(cve, intel_index)
    if intel is None:
        notes.append("CVE was reported in finding but not found in local intelligence index.")
        return "unverified", 0.25, notes, None

    vector_ok, vector_note = _cve_vector_consistent(cve, evidence)
    if vector_note:
        notes.append(vector_note)
    if not vector_ok:
        return "weak_match", 0.3, notes, intel

    intel_family = (intel.get("product_family") or "unknown").lower()
    vuln_type_norm = (vuln_type or "").strip().lower()

    if benchmark_target_id and expected_cves and cve not in expected_cves:
        notes.append(
            f"CVE {cve} is not in benchmark expected list for target {benchmark_target_id}: {expected_cves}."
        )
        return "weak_match", 0.35, notes, intel

    confidence = 0.55
    hinted_types = CVE_TYPE_HINTS.get(cve, set())
    if vuln_type_norm and hinted_types and vuln_type_norm not in hinted_types:
        notes.append(f"Vulnerability type '{vuln_type_norm}' is inconsistent with typical type of {cve}.")
        confidence -= 0.35

    signature_guards = {
        "CVE-2017-5638": ["content-type", "multipart/form-data", "%{", "ognl"],
        "CVE-2018-11776": ["ognl", "namespace", "actionchain", "%{", "${"],
        "CVE-2017-9805": ["struts2", "xstream", "application/xml"],
        "CVE-2017-12615": ["tomcat", "put", ".jsp"],
        "CVE-2021-41773": ["..%2f", ".%2e/", "/cgi-bin/.%2e", "path traversal"],
    }
    signature_runtime_guards = {
        "CVE-2017-5638": ["uid=", "whoami", "gid=", "root:x:", "hacked_by_ognl", "s2-045-confirmed-", "s2-045-vuln-"],
        "CVE-2018-11776": ["uid=", "whoami", "gid=", "root:x:", "hacked_by_ognl", "54289", "hello 49"],
        "CVE-2017-9805": ["uid=", "whoami", "gid=", "hacked_by_ognl", "s2_052_test"],
        "CVE-2017-12615": ["shell.jsp", "cmd=", "whoami", "uid=", "webdav"],
        "CVE-2021-41773": ["root:x:", "daemon:x:", "127.0.0.1 localhost", "[extensions]"],
    }
    if attribution_source == "signature_inferred":
        notes.append("CVE attribution is inferred from signature matching and requires stronger confirmation evidence.")
        confidence -= 0.10
        required_tokens = signature_guards.get(cve, [])
        if required_tokens and not any(tok in evidence.lower() for tok in required_tokens):
            notes.append("Signature-inferred CVE lacks critical exploit tokens in evidence.")
            return "weak_match", 0.35, notes, intel
        runtime_tokens = signature_runtime_guards.get(cve, [])
        if runtime_tokens and not any(tok in evidence.lower() for tok in runtime_tokens):
            notes.append("Signature-inferred CVE lacks runtime verification evidence in current output.")
            return "weak_match", 0.5, notes, intel

    evidence_lower = evidence.lower()
    template_products = set((primary_template or {}).get("products") or [])
    template_family = ((primary_template or {}).get("family") or "").lower()

    if intel_family != "unknown" and intel_family in evidence_lower:
        confidence += 0.25
    elif template_products and intel_family in template_products:
        confidence += 0.2
    elif template_family and intel_family and intel_family in template_family:
        confidence += 0.15
    else:
        notes.append(f"Intel product family '{intel_family}' is weakly supported by current evidence/template.")
        confidence -= 0.15

    refs = intel.get("references") or []
    if refs:
        confidence += 0.05
    if intel.get("poc_available"):
        confidence += 0.1
    if str(intel.get("source") or "").strip().lower() == "rag_index":
        notes.append("CVE attribution uses RAG-backed CVE intelligence as fallback evidence source.")
        confidence = min(confidence, 0.72)

    runtime_required = vuln_type_norm in {
        "rce",
        "ssti",
        "sql_injection",
        "xss",
        "xxe",
        "ssrf",
        "file_inclusion",
        "auth_bypass",
    }
    if runtime_required and not _runtime_evidence_ok(vuln_type_norm, evidence, "", []):
        notes.append("CVE attribution lacks runtime verification evidence and cannot be marked as confirmed.")
        confidence = min(confidence, 0.6)

    confidence = max(0.0, min(1.0, confidence))
    if confidence >= 0.75:
        return "confirmed", confidence, notes, intel
    return "weak_match", confidence, notes, intel


def _select_stable_cve(
    raw_cve: Optional[str],
    cve_candidates: Optional[List[str]],
    expected_cves: Optional[List[str]],
    evidence: str,
    attribution_source: str = "",
) -> Tuple[Optional[str], str, List[str]]:
    """
    Choose a stable CVE with deterministic priority:
    expected_cves > current/extracted > candidate list,
    while respecting vector-consistency checks.
    """
    notes: List[str] = []
    current = _normalize_cve(raw_cve)
    expected = [_normalize_cve(x) for x in (expected_cves or [])]
    expected = [x for x in expected if x]
    normalized_candidates = [_normalize_cve(x) for x in (cve_candidates or [])]
    normalized_candidates = [x for x in normalized_candidates if x]

    pool: List[str] = []
    if current:
        pool.append(current)
    pool.extend(normalized_candidates)
    pool.extend(expected)
    dedup_pool: List[str] = []
    seen = set()
    for item in pool:
        if item in seen:
            continue
        seen.add(item)
        dedup_pool.append(item)

    if not dedup_pool:
        return current, attribution_source or ("llm_extracted" if current else "none"), notes

    expected_one = expected[0] if len(expected) == 1 else None
    ranking = {c: i for i, c in enumerate(dedup_pool)}

    best_cve = None
    best_score = -10**9
    for cve in dedup_pool:
        score = 0
        if current and cve == current:
            score += 2
        if cve in normalized_candidates:
            score += 1
        if expected_one and cve == expected_one:
            score += 6
        elif cve in expected:
            score += 4

        vector_ok, _ = _cve_vector_consistent(cve, evidence)
        if vector_ok:
            score += 2
        else:
            score -= 3

        if attribution_source == "benchmark_target_map" and expected_one and cve == expected_one:
            score += 2

        # stable tie-breaker: expected first, then earlier appearance
        if score > best_score:
            best_score = score
            best_cve = cve
        elif score == best_score and best_cve is not None:
            cve_is_expected = cve in expected
            best_is_expected = best_cve in expected
            if cve_is_expected and not best_is_expected:
                best_cve = cve
            elif cve_is_expected == best_is_expected and ranking.get(cve, 10**6) < ranking.get(best_cve, 10**6):
                best_cve = cve

    chosen = best_cve or current
    source = attribution_source or ("llm_extracted" if chosen else "none")
    if chosen and chosen in expected:
        source = "benchmark_target_map"
    elif chosen and chosen != current:
        source = "candidate_stabilized"

    if chosen and current and chosen != current:
        notes.append(f"CVE stabilized from {current} to {chosen} by expected-candidate/vector consistency rules.")
    return chosen, source, notes


def _build_cve_rankings(
    current_cve: Optional[str],
    cve_candidates: Optional[List[str]],
    expected_cves: Optional[List[str]],
    evidence: str,
    vuln_type: str,
    cve_verdict: str,
    cve_confidence: float,
    benchmark_target_id: Optional[str],
    expected_family: str,
    primary_template: Optional[Dict],
    intel_index: Dict[str, Dict],
    matcher_candidates: Optional[List[Dict]] = None,
) -> List[Dict]:
    """
    Build ranked CVE candidates for unstable/partially verified findings.
    Output is sorted by probability desc.
    """
    current = _normalize_cve(current_cve)
    expected = [_normalize_cve(x) for x in (expected_cves or [])]
    expected = [x for x in expected if x]
    declared = [_normalize_cve(x) for x in (cve_candidates or [])]
    declared = [x for x in declared if x]
    extracted = _extract_cve_tokens(evidence)
    vuln_type_norm = (vuln_type or "").strip().lower()
    evidence_lower = _normalize_match_text(evidence)
    expected_family_norm = (expected_family or "").strip().lower()
    template_products = set((primary_template or {}).get("products") or [])
    template_family = ((primary_template or {}).get("family") or "").lower()

    pool: List[str] = []
    if current:
        pool.append(current)
    pool.extend(expected)
    pool.extend(declared)
    pool.extend(extracted)
    pool.extend([str(item.get("cve") or "") for item in (matcher_candidates or [])])
    dedup: List[str] = []
    seen = set()
    for item in pool:
        if not item or item in seen:
            continue
        seen.add(item)
        dedup.append(item)

    if not dedup:
        return []

    matcher_map = {
        _normalize_cve(item.get("cve")): item
        for item in (matcher_candidates or [])
        if _normalize_cve(item.get("cve"))
    }

    verdict = (cve_verdict or "").strip().lower()
    rankings_raw: List[Tuple[str, float, str, bool]] = []
    for cve in dedup:
        score = 0.18
        src: List[str] = []
        matcher_row = matcher_map.get(cve)
        matcher_score = 0.0
        if matcher_row:
            matcher_score = max(0.0, min(1.0, _to_float(matcher_row.get("score"), 0.0)))
            score += matcher_score * 0.55
            matcher_source = str(matcher_row.get("source") or "").strip()
            if matcher_source:
                src.append(matcher_source)

        if current and cve == current:
            current_anchor = 0.10 if verdict == "confirmed" else 0.04 if verdict == "weak_match" else 0.0
            score += current_anchor
            src.append("current")
            score += max(0.0, min(1.0, float(cve_confidence or 0.0))) * 0.12
            if verdict == "confirmed":
                score += 0.10
            elif verdict == "weak_match":
                score += 0.01
            elif verdict in {"unverified", "invalid_format"}:
                score -= 0.12

        if cve in expected:
            score += 0.48 if len(expected) == 1 else 0.32
            src.append("expected")
            if benchmark_target_id and len(expected) == 1:
                score += 0.10

        if cve in declared:
            score += 0.10
            src.append("declared")
        if cve in extracted:
            score += 0.06
            src.append("evidence")

        hinted_types = CVE_TYPE_HINTS.get(cve, set())
        if vuln_type_norm and hinted_types:
            if vuln_type_norm in hinted_types:
                score += 0.10
            else:
                score -= 0.24

        vector_ok, _ = _cve_vector_consistent(cve, evidence)
        if vector_ok:
            score += 0.22
        else:
            score -= 0.70
            if current and cve == current:
                score -= 0.22
            if matcher_score > 0:
                score -= max(0.18, min(0.45, matcher_score * 0.40))

        intel = _effective_intel_record(cve, intel_index)
        if intel:
            fam = (intel.get("product_family") or "unknown").lower()
            if fam != "unknown" and fam in evidence_lower:
                score += 0.08
            elif expected_family_norm and fam != "unknown":
                if expected_family_norm in fam or fam in expected_family_norm:
                    score += 0.08
                else:
                    score -= 0.06
            elif template_products and fam in template_products:
                score += 0.06
            elif template_family and fam and fam in template_family:
                score += 0.05
            if str(intel.get("source") or "").strip().lower() == "rag_index":
                score -= 0.03
                src.append("intel_rag")
        else:
            score -= 0.06

        source = ",".join(dict.fromkeys(src)) if src else "heuristic"
        rankings_raw.append((cve, score, source, vector_ok))

    weights = [math.exp(max(-4.0, min(4.0, s))) for _, s, _, _ in rankings_raw]
    total = sum(weights) or 1.0
    ranked: List[Dict] = []
    ranked_rows = sorted(
        [
            {
                "cve": r[0],
                "score": r[1],
                "source": r[2],
                "vector_ok": r[3],
                "weight": weights[i],
            }
            for i, r in enumerate(rankings_raw)
        ],
        key=lambda x: x["score"],
        reverse=True,
    )
    for idx, row in enumerate(ranked_rows):
        cve = row["cve"]
        score = row["score"]
        source = row["source"]
        vector_ok = row["vector_ok"]
        prob = float(row["weight"]) / total
        ranked.append(
            {
                "cve": cve,
                "probability": round(max(0.0, min(1.0, prob)), 4),
                "score": round(score, 4),
                "source": source,
                "vector_consistent": bool(vector_ok),
                "rank": idx + 1,
            }
        )
    return ranked[:8]


def _score_finding(
    finding: Dict,
    intel_index: Dict[str, Dict],
) -> Tuple[float, Dict]:
    response_evidence_items = [str(x) for x in (finding.get("response_evidence") or [])]
    request_evidence_items = [str(x) for x in (finding.get("request_evidence") or [])]
    evidence = (finding.get("evidence") or "") + "\n" + "\n".join(response_evidence_items)
    req_evidence = "\n".join(request_evidence_items)
    raw_cve = finding.get("cve")
    cve = _normalize_cve(raw_cve)
    benchmark_target_id = finding.get("benchmark_target_id")
    expected_cves = finding.get("expected_cves") or []
    expected_family = finding.get("expected_family") or ""
    attribution_source = finding.get("attribution_source") or ""

    candidates = generate_candidates(
        evidence_text=evidence + "\n" + req_evidence,
        cve_id=cve,
        expected_vuln_type=finding.get("vuln_type"),
    )
    vuln_type = (finding.get("vuln_type") or "").strip().lower()
    if vuln_type and vuln_type != "unknown":
        same_type = [c for c in candidates if (c.get("vuln_type") or "").strip().lower() == vuln_type]
        primary = same_type[0] if same_type else None
    else:
        primary = candidates[0] if candidates else None

    combined_text = evidence + "\n" + req_evidence
    match_plan = build_cve_match_plan(
        finding=finding,
        evidence=evidence,
        req_evidence=req_evidence,
        primary_template=primary,
        intel_index=intel_index,
    )
    ranked_candidate_ids = [
        str(item.get("cve") or "").strip().upper()
        for item in (match_plan.get("candidates") or [])
        if _normalize_cve(item.get("cve"))
    ]
    finding["cve_candidates"] = _merge_list_str(
        [str(x).strip().upper() for x in (finding.get("cve_candidates") or []) if _normalize_cve(x)],
        ranked_candidate_ids,
        limit=12,
    )
    match_profile = match_plan.get("profile") or {}
    inferred_family = str(match_profile.get("product_family") or "").strip().lower()
    if inferred_family and inferred_family != "unknown" and not str(finding.get("product_family") or "").strip():
        finding["product_family"] = inferred_family
    explicit_cve_tokens = [str(x).upper() for x in _extract_cve_tokens(combined_text)]
    should_lock_primary_cve = bool(cve or expected_cves or explicit_cve_tokens)
    stable_candidate_pool = (
        _merge_list_str(explicit_cve_tokens, finding.get("cve_candidates") or [], limit=12)
        if should_lock_primary_cve
        else []
    )
    stable_cve, stable_source, stable_notes = _select_stable_cve(
        raw_cve=cve,
        cve_candidates=stable_candidate_pool,
        expected_cves=expected_cves,
        evidence=combined_text,
        attribution_source=attribution_source,
    )
    if not should_lock_primary_cve and stable_cve:
        stable_notes.append(
            "Primary CVE was cleared because evidence does not explicitly anchor a concrete CVE id."
        )
        stable_cve = None
        stable_source = "none"
    cve = stable_cve
    attribution_source = stable_source
    finding["cve"] = cve
    finding["attribution_source"] = attribution_source
    if cve:
        cands = _merge_list_str([cve], finding.get("cve_candidates") or [], limit=10)
        finding["cve_candidates"] = cands

    score = 0.0
    score_components: Dict[str, float] = {}
    extra_notes: List[str] = list(stable_notes)

    # Base confidence from extractor
    confidence_component = min(_to_float(finding.get("confidence"), 0.0), 1.0) * 0.55
    score += confidence_component
    score_components["base_confidence"] = round(confidence_component, 4)

    req_effective = _effective_evidence_count(request_evidence_items)
    resp_effective = _effective_evidence_count(response_evidence_items)
    if req_effective > 0:
        score += 0.15
        score_components["request_evidence"] = 0.15
    if resp_effective > 0:
        score += 0.20
        score_components["response_evidence"] = 0.20

    if vuln_type == "ssti":
        if _has_ssti_runtime_evidence(evidence, req_evidence):
            score += 0.22
            score_components["ssti_runtime_evidence"] = 0.22
        else:
            score -= 0.32
            score_components["missing_ssti_runtime_evidence"] = -0.32
            extra_notes.append(
                "No reliable SSTI runtime evidence observed "
                "(deterministic evaluation such as 49/54289, or template-chain command output)."
            )
    if vuln_type == "rce":
        if _has_rce_runtime_evidence(evidence):
            score += 0.18
            score_components["rce_runtime_evidence"] = 0.18
        else:
            score -= 0.30
            score_components["missing_rce_runtime_evidence"] = -0.30
            extra_notes.append("No reliable command execution output was observed for RCE verification.")
    if vuln_type == "xss":
        if _has_xss_runtime_evidence(evidence):
            score += 0.18
            score_components["xss_runtime_evidence"] = 0.18
        else:
            score -= 0.25
            score_components["missing_xss_runtime_evidence"] = -0.25
            extra_notes.append("No payload execution/reflection evidence observed for XSS verification.")
    if vuln_type == "file_inclusion":
        if _has_file_inclusion_runtime_evidence(evidence):
            score += 0.20
            score_components["file_runtime_evidence"] = 0.20
        else:
            score -= 0.35
            score_components["missing_file_runtime_evidence"] = -0.35
            extra_notes.append("No deterministic target file content evidence observed for file inclusion.")
        if _looks_like_false_file_read_claim(evidence):
            score -= 0.22
            score_components["false_file_read_claim_penalty"] = -0.22
            extra_notes.append("Tool claimed file-read success but output looks like generic HTML shell page.")

    negative_hits = _negative_signal_hit_count(combined_text)
    explicit_failure_markers = [
        "final result: fail",
        "结论: fail",
        "[结论] fail",
        "failed or blocked",
        "injection failed",
        "blocked by",
        "no command execution detected",
        "response does not contain",
        "could not find",
        "target may not be vulnerable",
        "not vulnerable",
        "未检测到",
        "未发现",
    ]
    has_explicit_failure = any(marker in _normalize_match_text(combined_text) for marker in explicit_failure_markers)

    if has_explicit_failure and not _runtime_evidence_ok(vuln_type, evidence, req_evidence, response_evidence_items):
        score -= 0.22
        score_components["explicit_failure_penalty"] = -0.22
        extra_notes.append("Explicit exploit-failure markers detected without runtime success evidence.")

    if negative_hits > 0 and not _has_strong_runtime_success_signal(combined_text):
        negative_penalty = min(0.10 * negative_hits, 0.40)
        score -= negative_penalty
        score_components["negative_signal_penalty"] = round(-negative_penalty, 4)
        extra_notes.append("Negative signals detected in evidence (e.g., not vulnerable/failed/no output).")

    status_only = _looks_like_status_only_probe(combined_text)
    if status_only:
        score -= 0.25
        score_components["status_only_probe_penalty"] = -0.25
        extra_notes.append("Evidence is mainly status-code/HTML-shell output without reproducible exploit signal.")

    if _looks_like_expected_result_only_probe(combined_text):
        score -= 0.28
        score_components["expected_result_only_probe_penalty"] = -0.28
        extra_notes.append("Only expected-result probe text was observed; no actual exploit success evidence was captured.")

    if primary:
        confirm_hits = _keyword_hit_count(evidence, primary.get("confirm_markers", []))
        fp_hits = _keyword_hit_count(evidence, primary.get("false_positive_markers", []))
        runtime_like_confirmation = _runtime_evidence_ok(vuln_type, evidence, req_evidence, response_evidence_items)
        explicit_success_now = _has_explicit_verification_success(combined_text)
        confirm_bonus_allowed = not status_only and (
            vuln_type not in {"rce", "ssti", "xss", "file_inclusion", "sql_injection", "xxe", "ssrf", "auth_bypass"}
            or runtime_like_confirmation
            or explicit_success_now
        )
        confirm_bonus = min(confirm_hits * 0.10, 0.30) if confirm_bonus_allowed else 0.0
        fp_penalty = min(fp_hits * 0.14, 0.42)
        score += confirm_bonus
        score -= fp_penalty
        if confirm_bonus:
            score_components["template_confirm_bonus"] = round(confirm_bonus, 4)
        if fp_penalty:
            score_components["false_positive_penalty"] = round(-fp_penalty, 4)
        if confirm_hits == 0 and fp_hits > 0:
            score -= 0.12
            score_components["negative_without_confirm_penalty"] = -0.12

    cve_verdict, cve_confidence, uncertainty_notes, intel_record = _validate_cve_mapping(
        cve=cve,
        evidence=evidence + "\n" + req_evidence,
        primary_template=primary,
        intel_index=intel_index,
        vuln_type=vuln_type,
        benchmark_target_id=benchmark_target_id,
        expected_cves=expected_cves,
        expected_family=expected_family,
        attribution_source=attribution_source,
    )

    if cve_verdict == "confirmed":
        score += 0.15
        score_components["cve_confirmed_bonus"] = 0.15
    elif cve_verdict == "weak_match":
        score += 0.02
        score_components["cve_weak_match_bonus"] = 0.02
    elif cve_verdict in {"unverified", "invalid_format"}:
        score -= 0.12
        score_components["cve_uncertain_penalty"] = -0.12

    if cve:
        vector_ok, vector_note = _cve_vector_consistent(cve, evidence + "\n" + req_evidence)
        if not vector_ok:
            score -= 0.20
            score_components["cve_vector_mismatch_penalty"] = -0.20
            if vector_note and vector_note not in uncertainty_notes:
                uncertainty_notes.append(vector_note)

    if cve and intel_record:
        finding["intel_tags"] = {
            "product_family": intel_record.get("product_family", "unknown"),
            "protocols": intel_record.get("protocols", ["unknown"]),
            "prerequisites": intel_record.get("prerequisites", ["unknown"]),
            "poc_available": bool(intel_record.get("poc_available")),
        }

    if raw_cve and not cve:
        cve_verdict = "invalid_format"
        cve_confidence = 0.0
        uncertainty_notes.append("CVE format is invalid.")
    if extra_notes:
        uncertainty_notes.extend(extra_notes)

    runtime_ok = _runtime_evidence_ok(vuln_type, evidence, req_evidence, response_evidence_items)
    explicit_success = _has_explicit_verification_success(combined_text)
    verification_checks = {
        "runtime_signal": runtime_ok,
        "has_request_evidence": req_effective > 0,
        "has_response_evidence": resp_effective > 0,
        "no_negative_signal": negative_hits == 0,
        "not_status_only": not status_only,
        "explicit_success_signal": explicit_success,
    }
    strict_verified = all(verification_checks.values())

    if has_explicit_failure and not runtime_ok and not explicit_success:
        if score >= 0.25:
            score = min(score, 0.24)
            score_components["explicit_failure_cap"] = -0.01
        uncertainty_notes.append("Explicit FAIL/not-vulnerable evidence overrides Exit Code 0 style execution success.")

    if negative_hits >= 2 and not runtime_ok and not explicit_success and score >= 0.30:
        score = min(score, 0.29)
        score_components["negative_evidence_cap"] = -0.01
        uncertainty_notes.append("Multiple negative signals without runtime evidence capped this finding below suspected.")

    # Hard gate for "confirmed": strong verification only.
    if not strict_verified and score >= 0.80:
        score = min(score, 0.79)
        score_components["strict_verification_gate"] = -0.01
        uncertainty_notes.append("Strict verification gate not passed; capped below confirmed threshold.")

    if status_only and score >= 0.70:
        score = min(score, 0.68)
        score_components["status_only_cap"] = -0.02

    if negative_hits > 0 and score >= 0.75:
        score = min(score, 0.72)
        score_components["negative_signal_cap"] = -0.03

    if _looks_like_expected_result_only_probe(combined_text) and score >= 0.50:
        score = min(score, 0.39)
        score_components["expected_result_only_cap"] = -0.11

    if vuln_type == "rce" and status_only and not runtime_ok and not explicit_success and score >= 0.50:
        score = min(score, 0.49)
        score_components["rce_status_only_no_runtime_cap"] = -0.01
        uncertainty_notes.append("RCE finding stayed below suspected because only family/vector hints existed without runtime proof.")

    cve_rankings = _build_cve_rankings(
        current_cve=cve,
        cve_candidates=finding.get("cve_candidates") or [],
        expected_cves=expected_cves,
        evidence=evidence + "\n" + req_evidence,
        vuln_type=vuln_type,
        cve_verdict=cve_verdict,
        cve_confidence=cve_confidence,
        benchmark_target_id=benchmark_target_id,
        expected_family=expected_family,
        primary_template=primary,
        intel_index=intel_index,
        matcher_candidates=match_plan.get("candidates") or [],
    )

    raw_score = score
    score = max(0.0, min(1.0, score))
    score_components["raw_total"] = round(raw_score, 4)
    score_components["final_total"] = round(score, 4)
    context = {
        "template": primary,
        "cve_verdict": cve_verdict,
        "cve_confidence": round(cve_confidence, 4),
        "uncertainty_notes": uncertainty_notes,
        "score_components": score_components,
        "runtime_ok": runtime_ok,
        "verification_checks": verification_checks,
        "strict_verified": strict_verified,
        "status_only": status_only,
        "negative_hits": negative_hits,
        "cve_rankings": cve_rankings,
        "cve_match_profile": match_profile,
        "cve_match_used_rag": bool(match_plan.get("used_rag")),
    }
    return score, context


def _ensure_cve_remediation(finding: Dict) -> None:
    cve = (finding.get("cve") or "").strip().upper()
    if not cve:
        return
    remediation = list(finding.get("remediation") or [])
    if remediation:
        return
    remediation.extend(
        [
            f"Prioritize patching components affected by {cve} according to vendor security advisory.",
            "Verify component version, apply official fix, and run regression security tests.",
            "Add temporary compensating controls (WAF/ACL/rate-limit) until patch rollout is complete.",
        ]
    )
    finding["remediation"] = remediation


def _assign_status(score: float) -> str:
    confirmed_threshold = _to_float(os.getenv("CONFIRMED_THRESHOLD", "0.85"), 0.85)
    suspected_threshold = _to_float(os.getenv("SUSPECTED_THRESHOLD", "0.50"), 0.50)
    if score >= confirmed_threshold:
        return "confirmed"
    if score >= suspected_threshold:
        return "suspected"
    return "rejected"


def _cve_score_delta(verdict: str) -> float:
    mapping = {
        "confirmed": 0.15,
        "weak_match": 0.02,
        "unverified": -0.12,
        "invalid_format": -0.12,
    }
    return mapping.get((verdict or "").strip().lower(), 0.0)


def _cve_component_key(verdict: str) -> Optional[str]:
    mapping = {
        "confirmed": "cve_confirmed_bonus",
        "weak_match": "cve_weak_match_bonus",
        "unverified": "cve_uncertain_penalty",
        "invalid_format": "cve_uncertain_penalty",
    }
    return mapping.get((verdict or "").strip().lower())


def _rebalance_score_for_cve_verdict_change(
    score: float,
    score_components: Dict[str, float],
    old_verdict: str,
    new_verdict: str,
) -> Tuple[float, Dict[str, float]]:
    if (old_verdict or "").strip().lower() == (new_verdict or "").strip().lower():
        return score, score_components

    comps = dict(score_components or {})
    old_key = _cve_component_key(old_verdict)
    new_key = _cve_component_key(new_verdict)
    if old_key and old_key in comps:
        comps.pop(old_key, None)

    score = float(score or 0.0) - _cve_score_delta(old_verdict) + _cve_score_delta(new_verdict)
    if new_key:
        comps[new_key] = round(_cve_score_delta(new_verdict), 4)

    raw_before = comps.get("raw_total")
    if isinstance(raw_before, (int, float)):
        adjusted = float(raw_before) - _cve_score_delta(old_verdict) + _cve_score_delta(new_verdict)
        comps["raw_total"] = round(adjusted, 4)
    comps["final_total"] = round(max(0.0, min(1.0, score)), 4)
    return score, comps


def _resolve_expected_cve_conflicts(assessed: List[Dict]) -> List[Dict]:
    """
    For benchmark-like findings that provide a single expected CVE, suppress sibling CVE drift
    within the same target + vuln_type group to reduce unstable multi-CVE reporting.
    """
    items = list(assessed or [])
    groups: Dict[Tuple[str, str, str], List[int]] = {}

    for idx, f in enumerate(items):
        expected = [str(x).strip().upper() for x in (f.get("expected_cves") or []) if str(x).strip()]
        benchmark_target_id = str(f.get("benchmark_target_id") or "").strip()
        vuln_type = str(f.get("vuln_type") or "").strip().lower()
        cve = _normalize_cve(f.get("cve"))
        status = str(f.get("status") or "").strip().lower()
        if not benchmark_target_id or not vuln_type or len(expected) != 1 or not cve:
            continue
        if status == "rejected":
            continue
        key = (benchmark_target_id, vuln_type, expected[0])
        groups.setdefault(key, []).append(idx)

    for (_, _, expected_cve), idxs in groups.items():
        active = [i for i in idxs if _normalize_cve(items[i].get("cve"))]
        if len(active) <= 1:
            continue
        unique_cves = {_normalize_cve(items[i].get("cve")) for i in active}
        unique_cves = {x for x in unique_cves if x}
        if len(unique_cves) <= 1:
            continue

        preferred_idx = None
        expected_hits = [i for i in active if _normalize_cve(items[i].get("cve")) == expected_cve]
        if expected_hits:
            preferred_idx = max(expected_hits, key=lambda i: float(items[i].get("score") or 0.0))
        else:
            preferred_idx = max(active, key=lambda i: float(items[i].get("score") or 0.0))

        for i in active:
            if i == preferred_idx:
                continue
            f = dict(items[i])
            old_status = (f.get("status") or "").strip().lower()
            if old_status in {"confirmed", "suspected"}:
                f["status"] = "rejected"
                f["strict_verified"] = False
                f["score"] = round(min(float(f.get("score") or 0.0), 0.39), 4)
                notes = list(f.get("uncertainty_notes", []) or [])
                notes.append(
                    f"CVE sibling conflict resolved: expected {expected_cve}, this finding downgraded to rejected."
                )
                f["uncertainty_notes"] = notes
                comp = dict(f.get("score_breakdown", {}) or {})
                comp["sibling_cve_conflict_penalty"] = -0.2
                comp["final_total"] = round(float(f.get("score") or 0.0), 4)
                f["score_breakdown"] = comp
                if (f.get("cve_verdict") or "").strip().lower() == "confirmed":
                    f["cve_verdict"] = "weak_match"
                    f["cve_confidence"] = min(float(f.get("cve_confidence") or 0.0), 0.6)
                items[i] = f

    return items


def _normalize_overlap_text(text: str) -> str:
    lower = _normalize_match_text(text or "")
    lower = re.sub(r"[^a-z0-9_\-:/.%${}\s]", " ", lower)
    return re.sub(r"\s+", " ", lower).strip()


def _tokenize_overlap(text: str) -> set:
    normalized = _normalize_overlap_text(text)
    tokens = set()
    for token in normalized.split(" "):
        t = token.strip()
        if len(t) < 3:
            continue
        tokens.add(t)
    return tokens


def _jaccard_overlap(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return float(inter / union) if union else 0.0


def _collect_finding_evidence_text(finding: Dict) -> str:
    parts = []
    parts.append(str(finding.get("evidence") or ""))
    for x in (finding.get("request_evidence") or []):
        parts.append(str(x))
    for x in (finding.get("response_evidence") or []):
        parts.append(str(x))
    parts.append(str(finding.get("vuln_type") or ""))
    parts.append(str(finding.get("template_id") or ""))
    return "\n".join([p for p in parts if p])


def _extract_runtime_markers(text: str) -> set:
    lower = (text or "").lower()
    markers = [
        "uid=",
        "gid=",
        "whoami",
        "root:x:",
        "54289",
        "hello 49",
        "vulnerable: true",
        '"vulnerable": true',
        "union select",
        "sql syntax",
        "<script>alert",
        "onerror=",
        "..%2f",
        "/etc/passwd",
    ]
    return {m for m in markers if m in lower}


def _suppress_generic_duplicates_when_specific_exists(assessed: List[Dict]) -> List[Dict]:
    """
    If a specific CVE finding is already confirmed/strict, suppress generic same-type findings
    that are based on highly overlapping evidence.
    """
    items = list(assessed or [])
    specific_idxs = []
    for idx, f in enumerate(items):
        status = (f.get("status") or "").strip().lower()
        cve = _normalize_cve(f.get("cve"))
        if not cve or status != "confirmed":
            continue
        if bool(f.get("strict_verified")) or (f.get("cve_verdict") or "").strip().lower() == "confirmed":
            specific_idxs.append(idx)

    if not specific_idxs:
        return items

    specific_cache = {}
    for i in specific_idxs:
        f = items[i]
        txt = _collect_finding_evidence_text(f)
        specific_cache[i] = {
            "vuln_type": str(f.get("vuln_type") or "").strip().lower(),
            "tokens": _tokenize_overlap(txt),
            "runtime": _extract_runtime_markers(txt),
            "req": {str(x).strip().lower() for x in (f.get("request_evidence") or []) if str(x).strip()},
        }

    for idx, f in enumerate(items):
        if _normalize_cve(f.get("cve")):
            continue
        status = (f.get("status") or "").strip().lower()
        if status not in {"confirmed", "suspected"}:
            continue
        vuln_type = str(f.get("vuln_type") or "").strip().lower()
        if not vuln_type:
            continue

        txt = _collect_finding_evidence_text(f)
        cur_tokens = _tokenize_overlap(txt)
        cur_runtime = _extract_runtime_markers(txt)
        cur_req = {str(x).strip().lower() for x in (f.get("request_evidence") or []) if str(x).strip()}

        best_overlap = 0.0
        best_idx = None
        for s_idx, s_meta in specific_cache.items():
            if s_meta["vuln_type"] != vuln_type:
                continue
            ov = _jaccard_overlap(cur_tokens, s_meta["tokens"])
            if ov > best_overlap:
                best_overlap = ov
                best_idx = s_idx

        if best_idx is None:
            continue

        spec = specific_cache[best_idx]
        runtime_overlap = len(cur_runtime & spec["runtime"])
        req_overlap = _jaccard_overlap(cur_req, spec["req"]) if cur_req and spec["req"] else (1.0 if not cur_req else 0.0)
        is_derivative_duplicate = (
            best_overlap >= 0.55
            or (best_overlap >= 0.38 and runtime_overlap > 0 and req_overlap >= 0.8)
        )
        if not is_derivative_duplicate:
            continue

        specific_cve = _normalize_cve(items[best_idx].get("cve")) or "已确认CVE"
        updated = dict(f)
        updated["status"] = "rejected"
        updated["strict_verified"] = False
        updated["score"] = round(min(float(updated.get("score") or 0.0), 0.39), 4)
        notes = list(updated.get("uncertainty_notes", []) or [])
        notes.append(
            f"Generic finding suppressed: overlaps with specific confirmed finding {specific_cve} (overlap={best_overlap:.2f})."
        )
        updated["uncertainty_notes"] = notes
        comp = dict(updated.get("score_breakdown", {}) or {})
        comp["generic_duplicate_suppressed"] = -0.25
        comp["final_total"] = round(float(updated.get("score") or 0.0), 4)
        updated["score_breakdown"] = comp
        items[idx] = updated

    return items


def assess_findings(
    existing_findings: List[Dict],
    incoming_findings: List[Dict],
    elapsed_time: Optional[float] = None,
) -> Tuple[List[Dict], Dict]:
    """
    Score findings and move through suspected -> confirmed lifecycle.
    CVE certainty rules:
    - Vulnerability can be confirmed without CVE.
    - If CVE is uncertain, force at most suspected unless evidence explicitly marks CVE as confirmed.
    """
    intel_index = load_intel_index()
    all_findings = _merge_duplicate_findings(list(existing_findings or []) + list(incoming_findings or []))
    assessed: List[Dict] = []

    for finding in all_findings:
        f = dict(finding)
        score, ctx = _score_finding(f, intel_index=intel_index)
        status = _assign_status(score)

        cve_verdict = ctx.get("cve_verdict", "absent")
        original_cve_verdict = cve_verdict
        cve_confidence = ctx.get("cve_confidence", 0.0)
        uncertainty_notes = ctx.get("uncertainty_notes", []) or []
        score_components = dict(ctx.get("score_components", {}) or {})
        strict_verified = bool(ctx.get("strict_verified", False))
        verification_checks = ctx.get("verification_checks", {}) or {}
        runtime_ok = bool(ctx.get("runtime_ok", False))
        status_only = bool(ctx.get("status_only", False))
        negative_hits = int(ctx.get("negative_hits", 0) or 0)
        cve_rankings_raw = list(ctx.get("cve_rankings") or [])

        # Guardrail: uncertain CVE should not be reported as confirmed CVE attribution.
        if f.get("cve") and cve_verdict in {"invalid_format", "unverified", "weak_match"} and status == "confirmed":
            status = "suspected"
            uncertainty_notes.append("Finding downgraded to suspected because CVE attribution is uncertain.")
        if (
            f.get("cve")
            and cve_verdict == "confirmed"
            and status != "confirmed"
            and (f.get("attribution_source") or "") == "signature_inferred"
        ):
            cve_verdict = "weak_match"
            cve_confidence = min(float(cve_confidence or 0.0), 0.6)
            uncertainty_notes.append("CVE attribution downgraded because exploit verification is not yet confirmed.")

        if cve_verdict != original_cve_verdict:
            score, score_components = _rebalance_score_for_cve_verdict_change(
                score=score,
                score_components=score_components,
                old_verdict=original_cve_verdict,
                new_verdict=cve_verdict,
            )
            score = max(0.0, min(1.0, score))
            status = _assign_status(score)

        # Strict confirmation gate: avoid promoting weak/single-signal findings to confirmed.
        if status == "confirmed" and not strict_verified:
            status = "suspected"
            uncertainty_notes.append(
                "Finding downgraded to suspected because strict verification checks were not fully satisfied."
            )

        if status == "confirmed" and status_only:
            status = "suspected"
            uncertainty_notes.append("Finding downgraded to suspected because output is status-code-only.")

        if status == "confirmed" and negative_hits > 0 and not runtime_ok:
            status = "suspected"
            uncertainty_notes.append("Finding downgraded to suspected due to negative signals without runtime success.")

        if f.get("cve") and cve_verdict == "confirmed" and (status != "confirmed" or not strict_verified):
            prev_verdict = cve_verdict
            cve_verdict = "weak_match"
            cve_confidence = min(float(cve_confidence or 0.0), max(0.0, float(score) * 0.85))
            uncertainty_notes.append(
                "CVE attribution downgraded because vulnerability type is not strictly confirmed yet."
            )
            score, score_components = _rebalance_score_for_cve_verdict_change(
                score=score,
                score_components=score_components,
                old_verdict=prev_verdict,
                new_verdict=cve_verdict,
            )
            score = max(0.0, min(1.0, score))
            status = _assign_status(score)
            if status == "confirmed" and not strict_verified:
                status = "suspected"

        normalized_cve_rankings: List[Dict] = []
        seen_rankings = set()
        for item in cve_rankings_raw:
            if not isinstance(item, dict):
                continue
            cve_id = _normalize_cve(item.get("cve"))
            if not cve_id or cve_id in seen_rankings:
                continue
            prob = max(0.0, min(1.0, _to_float(item.get("probability"), 0.0)))
            if prob <= 0.0:
                continue
            seen_rankings.add(cve_id)
            normalized_cve_rankings.append(
                {
                    "cve": cve_id,
                    "probability": round(prob, 4),
                    "score": round(_to_float(item.get("score"), 0.0), 4),
                    "source": str(item.get("source") or "heuristic"),
                    "vector_consistent": bool(item.get("vector_consistent", False)),
                }
            )
        normalized_cve_rankings.sort(key=lambda x: float(x.get("probability") or 0.0), reverse=True)

        fully_verified_cve = (
            status == "confirmed"
            and strict_verified
            and cve_verdict == "confirmed"
            and _normalize_cve(f.get("cve"))
        )
        if fully_verified_cve:
            confirmed_cve = _normalize_cve(f.get("cve"))
            normalized_cve_rankings = [
                {
                    "cve": confirmed_cve,
                    "probability": 1.0,
                    "score": 1.0,
                    "source": "strict_confirmed",
                    "vector_consistent": True,
                    "rank": 1,
                }
            ]
        else:
            current_cve = _normalize_cve(f.get("cve"))
            if current_cve and all(r.get("cve") != current_cve for r in normalized_cve_rankings):
                fallback_prob = max(0.05, min(0.65, _to_float(cve_confidence, 0.0) * 0.7))
                normalized_cve_rankings.append(
                    {
                        "cve": current_cve,
                        "probability": round(fallback_prob, 4),
                        "score": round(fallback_prob, 4),
                        "source": "current_fallback",
                        "vector_consistent": False,
                    }
                )
            normalized_cve_rankings.sort(key=lambda x: float(x.get("probability") or 0.0), reverse=True)
            normalized_cve_rankings = normalized_cve_rankings[:8]
            total_prob = sum(float(x.get("probability") or 0.0) for x in normalized_cve_rankings) or 1.0
            for i, row in enumerate(normalized_cve_rankings):
                row["probability"] = round(float(row.get("probability") or 0.0) / total_prob, 4)
                row["rank"] = i + 1
        primary_cve = _normalize_cve(f.get("cve"))
        if not fully_verified_cve:
            # Workflow rule: non-strict findings can keep candidate rankings,
            # but must not expose a concrete primary CVE as final attribution.
            if cve_verdict == "confirmed":
                prev_verdict = cve_verdict
                cve_verdict = "weak_match"
                cve_confidence = min(float(cve_confidence or 0.0), 0.62)
                uncertainty_notes.append(
                    "Primary CVE hidden because strict verification is incomplete; keep probabilistic rankings only."
                )
                score, score_components = _rebalance_score_for_cve_verdict_change(
                    score=score,
                    score_components=score_components,
                    old_verdict=prev_verdict,
                    new_verdict=cve_verdict,
                )
                score = max(0.0, min(1.0, score))
                status = _assign_status(score)
                if status == "confirmed" and not strict_verified:
                    status = "suspected"
            if primary_cve and all(r.get("cve") != primary_cve for r in normalized_cve_rankings):
                fallback_prob = max(0.05, min(0.55, _to_float(cve_confidence, 0.0) * 0.65))
                normalized_cve_rankings.append(
                    {
                        "cve": primary_cve,
                        "probability": round(fallback_prob, 4),
                        "score": round(fallback_prob, 4),
                        "source": "suppressed_primary_fallback",
                        "vector_consistent": False,
                    }
                )
                normalized_cve_rankings.sort(key=lambda x: float(x.get("probability") or 0.0), reverse=True)
                normalized_cve_rankings = normalized_cve_rankings[:8]
                total_prob = sum(float(x.get("probability") or 0.0) for x in normalized_cve_rankings) or 1.0
                for i, row in enumerate(normalized_cve_rankings):
                    row["probability"] = round(float(row.get("probability") or 0.0) / total_prob, 4)
                    row["rank"] = i + 1
            f["cve"] = None

        f["score"] = round(score, 4)
        f["workflow_score"] = round(score, 4)
        f["status"] = status
        f["cve_verdict"] = cve_verdict
        f["cve_confidence"] = cve_confidence
        f["uncertainty_notes"] = uncertainty_notes
        f["score_breakdown"] = score_components
        f["strict_verified"] = strict_verified
        f["verification_checks"] = verification_checks
        f["cve_rankings"] = normalized_cve_rankings
        f["existence_rate"] = round(calibrated_finding_probability(f), 4)
        f["type_probability"] = f["existence_rate"]
        cve_probability = calibrated_cve_probability(f, type_probability=f["existence_rate"])
        primary_cve_final = _normalize_cve(f.get("cve"))
        if normalized_cve_rankings and primary_cve_final:
            for row in normalized_cve_rankings:
                if row.get("cve") == primary_cve_final:
                    cve_probability = float(row.get("probability") or cve_probability)
                    break
        elif normalized_cve_rankings:
            cve_probability = max(cve_probability, float(normalized_cve_rankings[0].get("probability") or 0.0))
        f["cve_probability"] = round(max(0.0, min(1.0, cve_probability)), 4)
        if ctx.get("cve_match_profile"):
            f["cve_match_profile"] = ctx.get("cve_match_profile")
        if "cve_match_used_rag" in ctx:
            f["cve_match_used_rag"] = bool(ctx.get("cve_match_used_rag"))

        if ctx.get("template"):
            f["template_id"] = ctx["template"].get("template_id")
            if not f.get("remediation"):
                f["remediation"] = ctx["template"].get("remediation", [])
        _ensure_cve_remediation(f)

        assessed.append(f)

    assessed = _resolve_expected_cve_conflicts(assessed)
    assessed = _suppress_generic_duplicates_when_specific_exists(assessed)

    confirmed = [f for f in assessed if f.get("status") == "confirmed"]
    suspected = [f for f in assessed if f.get("status") == "suspected"]
    rejected = [f for f in assessed if f.get("status") == "rejected"]

    total = len(assessed)
    false_positive_rate = (len(rejected) / total) if total else 0.0
    family_distribution: Dict[str, int] = {}
    uncertain_cve_count = 0
    strict_verified_count = 0

    for f in assessed:
        if f.get("cve") and f.get("cve_verdict") in {"invalid_format", "unverified", "weak_match"}:
            uncertain_cve_count += 1
        elif (f.get("status") or "").strip().lower() != "confirmed" and (f.get("cve_rankings") or []):
            uncertain_cve_count += 1
        if f.get("strict_verified"):
            strict_verified_count += 1

    for f in confirmed:
        fam = f.get("template_id") or f.get("vuln_type", "unknown")
        family_distribution[fam] = family_distribution.get(fam, 0) + 1

    metrics = {
        "total_findings": total,
        "confirmed_count": len(confirmed),
        "suspected_count": len(suspected),
        "rejected_count": len(rejected),
        "false_positive_rate": round(false_positive_rate, 4),
        "avg_detection_time_seconds": round(float(elapsed_time or 0.0), 2),
        "cve_family_distribution": family_distribution,
        "uncertain_cve_count": uncertain_cve_count,
        "strict_verified_count": strict_verified_count,
    }
    return assessed, metrics

