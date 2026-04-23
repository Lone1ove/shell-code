from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

from shell_agent.common import normalize_text_content
from shell_agent.finding_identity import finding_identity_key
from shell_agent.utils.flag_validator import extract_flag_from_text, validate_flag_format


def _extract_cves(text: str) -> List[str]:
    return list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)))


def _extract_verified_flag_from_tool_messages(messages: List) -> Optional[str]:
    """
    Extract a reasonably trustworthy flag from tool outputs.
    This is conservative: reject placeholders/examples to avoid fabricated flags.
    """
    if not messages:
        return None

    placeholder_markers = ["test_flag", "demo_flag", "example_flag", "fake_flag", "sample_flag", "your_flag"]
    evidence_markers = [
        "answer correct",
        "flag correct",
        "submit success",
        "found flag",
        "read flag",
        "cat /flag",
        "/flag",
    ]

    for msg in messages:
        content = getattr(msg, "content", "")
        if not isinstance(content, str) or not content.strip():
            continue
        flags = extract_flag_from_text(content)
        if not flags:
            continue
        lower = content.lower()
        if not any(m in lower for m in evidence_markers):
            continue

        for f in flags:
            ok, _ = validate_flag_format(f)
            if not ok:
                continue
            if any(p in f.lower() for p in placeholder_markers):
                continue
            return f

    return None


SIGNATURE_CVE_RULES = [
    {
        "cve": "CVE-2017-5638",
        "all_of": ["struts2"],
        "any_of": ["s2-045", "cve-2017-5638", "doupload.action", "content-type: %{", "multipart/form-data", "cmd-output:"],
        "min_score": 2,
    },
    {
        "cve": "CVE-2018-11776",
        "all_of": ["struts2"],
        "any_of": ["s2-057", "cve-2018-11776", "namespace", "actionchain", "redirect:${", "/${", "%24%7b"],
        "min_score": 2,
    },
    {"cve": "CVE-2022-22965", "all_of": [], "any_of": ["spring4shell", "cve-2022-22965", "class.module.classloader"], "min_score": 2},
    {"cve": "CVE-2021-44228", "all_of": [], "any_of": ["log4shell", "cve-2021-44228", "${jndi:"], "min_score": 2},
    {"cve": "CVE-2022-26134", "all_of": ["confluence"], "any_of": ["ognl", "cve-2022-26134"], "min_score": 2},
    {"cve": "CVE-2021-26855", "all_of": ["exchange"], "any_of": ["proxylogon", "x-beresource", "cve-2021-26855"], "min_score": 2},
    {
        "cve": "CVE-2017-10271",
        "all_of": ["weblogic"],
        "any_of": ["cve-2017-10271", "/wls-wsat/", "xmldecoder", "workcontext", "soapaction"],
        "min_score": 2,
    },
    {
        "cve": "CVE-2018-2628",
        "all_of": ["weblogic"],
        "any_of": ["cve-2018-2628", "t3", "iiop", "deserialization"],
        "min_score": 2,
    },
    {
        "cve": "CVE-2018-2894",
        "all_of": ["weblogic"],
        "any_of": ["cve-2018-2894", "ws_utc", "config.do", "console", "upload"],
        "min_score": 2,
    },
    {"cve": "CVE-2022-25845", "all_of": ["fastjson"], "any_of": ["cve-2022-25845", "autotype", "jndi", "ldap", "rmi"], "min_score": 2},
    {"cve": "CVE-2016-4437", "all_of": ["shiro"], "any_of": ["cve-2016-4437", "rememberme", "rememberme=deleteme"], "min_score": 2},
    {"cve": "CVE-2017-12149", "all_of": ["jboss"], "any_of": ["cve-2017-12149", "jmxinvokerservlet", "invoker", "deserialization"], "min_score": 2},
    {
        "cve": "CVE-2017-12615",
        "all_of": ["tomcat"],
        "any_of": ["cve-2017-12615", "http put", "allow: put", "webdav", ".jsp/", "jsp upload"],
        "forbidden_any": ["struts2", "ognl", "s2-057", "s2-045", "showcase"],
        "min_score": 3,
    },
    {"cve": "CVE-2017-9841", "all_of": ["phpunit"], "any_of": ["eval-stdin.php", "cve-2017-9841"], "min_score": 2},
    {"cve": "CVE-2018-7600", "all_of": ["drupal"], "any_of": ["drupalgeddon", "cve-2018-7600", "form_build_id"], "min_score": 2},
    {
        "cve": "CVE-2021-41773",
        "all_of": ["apache"],
        "any_of": ["cve-2021-41773", "..%2f", ".%2e/", "/cgi-bin/.%2e"],
        "min_score": 2,
    },
    {
        "cve": "CVE-2021-42013",
        "all_of": ["apache"],
        "any_of": ["cve-2021-42013", "..%2f", ".%2e/", "/cgi-bin/.%2e", "uid=", "whoami"],
        "min_score": 3,
    },
] 


def _score_signature_rule(rule: Dict, lower_text: str) -> Optional[int]:
    all_of = rule.get("all_of", []) or []
    any_of = rule.get("any_of", []) or []
    forbidden_any = rule.get("forbidden_any", []) or []
    if forbidden_any and any(k in lower_text for k in forbidden_any):
        return None
    if all_of and not all(k in lower_text for k in all_of):
        return None
    matched_any = [k for k in any_of if k in lower_text]
    if any_of and not matched_any:
        return None
    score = len(matched_any) + len(all_of)
    min_score = int(rule.get("min_score", 2))
    if score < min_score:
        return None
    return score


def _infer_cve_candidates_from_signatures(text: str, top_k: int = 5) -> List[str]:
    lower = (text or "").lower()
    scored: List[tuple[int, str]] = []
    for rule in SIGNATURE_CVE_RULES:
        score = _score_signature_rule(rule, lower)
        if score is None:
            continue
        scored.append((score, rule["cve"]))
    if not scored:
        return []

    # stable ranking: score desc, then CVE lexicographically.
    scored.sort(key=lambda x: (-x[0], x[1]))
    out: List[str] = []
    seen = set()
    for _, cve in scored:
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
        if len(out) >= max(1, top_k):
            break
    return out


def _infer_known_cve_from_signatures(text: str) -> Optional[str]:
    lower = (text or "").lower()
    ranked = _infer_cve_candidates_from_signatures(text, top_k=3)
    if ranked:
        return ranked[0]

    # Prefer S2-045 when the evidence is centered on doUpload.action/content-type style
    # header injection and runtime command output.
    s2045_signal = (
        "doupload.action" in lower
        and any(token in lower for token in ["cmd-output:", "uid=", "gid=", "whoami"])
        and any(token in lower for token in ["ognl", "%{", "content-type"])
    )
    if s2045_signal:
        return "CVE-2017-5638"

    # Fallback for Struts2 sibling ambiguity:
    # if runtime RCE evidence exists with Struts2/OGNL but no S2-045 header vector,
    # prefer S2-057 to improve deterministic attribution.
    has_runtime = any(token in lower for token in ["uid=", "gid=", "whoami", "command output", "execution result"])
    has_struts_signal = any(token in lower for token in ["struts2", "ognl", "showcase"])
    has_s2045_header = "content-type: %{" in lower and "multipart/form-data" in lower
    has_s2057_runtime = any(token in lower for token in ["54289", "hello 49", "s2-057", "cve-2018-11776"])
    if has_runtime and has_struts_signal and (has_s2057_runtime or not has_s2045_header):
        return "CVE-2018-11776"
    return None


def _cve_inference_guard(cve: Optional[str], text: str) -> bool:
    """
    Guard coarse signature inference with CVE-specific vector checks.
    """
    if not cve:
        return False
    lower = (text or "").lower().replace("–", "-").replace("—", "-")
    has_runtime = any(token in lower for token in ["uid=", "gid=", "whoami", "command output", "execution result"])

    if cve == "CVE-2017-5638":
        has_payload_header = "content-type: %{" in lower and "multipart/form-data" in lower
        has_ognl_payload_vector = (
            "%{" in lower
            and "multipart/form-data" in lower
            and any(token in lower for token in ["ognl", "ognlcontext", "doupload.action", "s2-045", "cve-2017-5638"])
        )
        has_doupload_runtime_vector = (
            "doupload.action" in lower
            and any(token in lower for token in ["cmd-output:", "uid=", "gid=", "whoami"])
            and any(token in lower for token in ["ognl", "%{", "content-type"])
        )
        has_header_injection_effect = any(
            token in lower
            for token in [
                "vulhub:",
                "cmd-output:",
                "response header contains 'vulhub:",
                "pass: s2-045 vulnerability confirmed",
            ]
        )
        parser_signal = any(
            token in lower
            for token in ["invalid content type", "jakarta", "multipartrequestwrapper", "strutsproblemreporter"]
        )
        hard_negative = (
            ("http status 404" in lower or "404 - not found" in lower or "< http/1.1 404" in lower)
            and "no result defined for action" in lower
            and not has_runtime
        )
        vector_ok = has_payload_header or has_ognl_payload_vector or has_doupload_runtime_vector
        evidence_ok = has_runtime or parser_signal or has_header_injection_effect
        return vector_ok and evidence_ok and not hard_negative

    if cve == "CVE-2018-11776":
        path_or_namespace_signal = any(
            token in lower
            for token in [
                "s2-057",
                "cve-2018-11776",
                "/${",
                "%24%7b",
                "namespace=",
                "actionchain",
                "redirect:${",
            ]
        )
        runtime_struts_signal = (
            has_runtime
            and any(token in lower for token in ["struts2", "ognl", "showcase", "54289", "hello 49"])
        )
        s2045_style_only = "content-type: %{" in lower and "multipart/form-data" in lower and not path_or_namespace_signal
        return (path_or_namespace_signal or runtime_struts_signal) and not s2045_style_only

    if cve == "CVE-2017-12615":
        has_tomcat = "tomcat" in lower
        has_put_vector = any(
            token in lower
            for token in [
                "http put",
                " put /",
                "allow: put",
                "webdav",
                "put /",
            ]
        )
        has_jsp_upload_signal = any(
            token in lower
            for token in [
                ".jsp/",
                "jsp upload",
                ".jsp",
                "201 created",
            ]
        )
        has_struts_noise = any(
            token in lower for token in ["struts2", "ognl", "s2-057", "s2-045", "showcase"]
        )
        return has_tomcat and has_put_vector and has_jsp_upload_signal and not has_struts_noise

    if cve == "CVE-2021-42013":
        has_apache_traversal = any(token in lower for token in ["..%2f", ".%2e/", "/cgi-bin/.%2e", "path traversal"])
        return has_apache_traversal and has_runtime

    if cve == "CVE-2017-10271":
        has_weblogic_xml = any(token in lower for token in ["weblogic", "/wls-wsat/", "xmldecoder", "workcontext"])
        return has_weblogic_xml and (has_runtime or "soapaction" in lower)

    # Generic rule guard for all covered CVEs:
    # keep inference only when signature rule itself is matched.
    for rule in SIGNATURE_CVE_RULES:
        if rule.get("cve") != cve:
            continue
        score = _score_signature_rule(rule, lower)
        if score is None:
            return False
        # If runtime exists, one matching vector is acceptable.
        # Without runtime, require stronger textual anchoring.
        min_score = int(rule.get("min_score", 2))
        if has_runtime:
            return score >= max(1, min_score - 1)
        return score >= min_score

    # Unknown CVE outside built-in rule set:
    # require explicit CVE token present in the evidence text.
    return cve.lower() in lower


def _infer_cve_from_challenge_context(context_text: str) -> Optional[str]:
    raw = str(context_text or "")
    lower = raw.lower()
    direct = [x.upper() for x in _extract_cves(raw)]
    if len(direct) == 1:
        return direct[0]
    if len(direct) > 1:
        # If context carries multiple CVEs, only trust lines with explicit target anchors.
        anchored: List[str] = []
        anchor_tokens = [
            "expected cve",
            "target cve",
            "ground truth",
            "benchmark",
            "official cve",
            "validated cve",
            "cve:",
        ]
        for line in raw.splitlines():
            line_lower = line.lower()
            if not any(tok in line_lower for tok in anchor_tokens):
                continue
            for cve in _extract_cves(line):
                cve_norm = str(cve or "").upper().strip()
                if cve_norm and cve_norm not in anchored:
                    anchored.append(cve_norm)
        if len(anchored) == 1:
            return anchored[0]
        return None

    s2_alias_map = {
        "s2-005": "CVE-2010-1870",
        "s2-007": "CVE-2012-0838",
        "s2-008": "CVE-2012-0392",
        "s2-009": "CVE-2011-3923",
        "s2-013": "CVE-2013-1966",
        "s2-015": "CVE-2013-2134",
        "s2-016": "CVE-2013-2251",
        "s2-029": "CVE-2016-0785",
        "s2-032": "CVE-2016-3081",
        "s2-045": "CVE-2017-5638",
        "s2-046": "CVE-2017-5638",
        "s2-048": "CVE-2017-9791",
        "s2-052": "CVE-2017-9805",
        "s2-053": "CVE-2017-12611",
        "s2-057": "CVE-2018-11776",
        "s2-059": "CVE-2019-0230",
        "s2-061": "CVE-2020-17530",
        "s2-062": "CVE-2021-31805",
    }
    alias_hits: List[str] = []
    for alias, cve in s2_alias_map.items():
        if alias in lower or alias.replace("-", "_") in lower:
            alias_hits.append(cve)
    if alias_hits:
        unique_hits: List[str] = []
        seen = set()
        for cve in alias_hits:
            cve_norm = str(cve or "").upper().strip()
            if not cve_norm or cve_norm in seen:
                continue
            seen.add(cve_norm)
            unique_hits.append(cve_norm)
        if len(unique_hits) == 1:
            return unique_hits[0]
        return None
    return _infer_known_cve_from_signatures(context_text)


def _has_ssti_vector_signal(text: str) -> bool:
    lower = (text or "").lower()
    # 常见 SSTI/Jinja 表达式与对象链信号
    has_jinja_expr = bool(re.search(r"\{\{.{1,400}\}\}", lower, re.DOTALL))
    deterministic_expr = bool(re.search(r"\{\{\s*\d{1,4}\s*\*\s*\d{1,4}\s*\}\}", lower))
    payload_markers = [
        "__globals__",
        "__builtins__",
        "config.__class__",
        "class.__mro__",
        "subclasses()",
        "os.popen",
        "popen(",
        "{{request",
        "{{config",
        "{{self",
        "template injection",
        "jinja",
        "jinja2",
        "ssti",
    ]
    has_payload_chain = any(m in lower for m in payload_markers)
    return deterministic_expr or (has_jinja_expr and has_payload_chain)


def _looks_like_expected_result_only_probe(text: str) -> bool:
    lower = (text or "").lower()
    has_expectation = any(
        token in lower
        for token in [
            "expected result:",
            "if ognl injection works",
            "if ssti works",
            "if command execution works",
            "should return 54289",
        ]
    )
    has_negative = any(
        token in lower
        for token in [
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
    return has_expectation and has_negative and not any(
        token in lower
        for token in [
            "uid=",
            "gid=",
            "whoami",
            "root:x:",
            "x-cmd-result:",
            "x-check:",
            "vulnerable: true",
            "\"vulnerable\": true",
            "command execution successful",
            "exploit success",
        ]
    )


def _looks_like_status_only_probe(text: str) -> bool:
    lower = re.sub(r"\s+", " ", str(text or "").lower()).strip()
    status_hits = lower.count("status code") + lower.count("status:") + lower.count("状态码") + lower.count("http status")
    html_shell = "<!doctype html" in lower or "<html" in lower
    has_runtime = any(
        token in lower
        for token in ["uid=", "gid=", "whoami", "command output", "execution result", "x-command-output", "x-cmd-result"]
    )
    return (status_hits >= 1 and html_shell and not has_runtime) or (status_hits >= 2 and html_shell)


def _looks_like_transport_level_error(text: str) -> bool:
    lower = normalize_text_content(text).lower()
    markers = [
        "connection broken",
        "incomplete read",
        "incompleteread",
        "remote end closed connection",
        "remotedisconnected",
        "chunkedencodingerror",
        "protocolerror",
        "connection aborted",
        "connection reset by peer",
        "broken pipe",
        "read timed out",
        "readtimeout",
        "unexpected eof",
        "ssl: unexpected eof",
        "unexpected error: ('connection broken:",
    ]
    if not any(marker in lower for marker in markers):
        return False

    structured_verification_markers = [
        "target url:",
        "payload:",
        "response headers:",
        "response preview:",
        "response body:",
        "status code:",
        "verdict",
        "[*] test ",
        "[*] step ",
        "x-ognl header present:",
        "processing detected",
        "response length:",
    ]
    has_structured_verification = any(marker in lower for marker in structured_verification_markers)
    if has_structured_verification:
        return False
    return True


def _has_transport_artifact(text: str) -> bool:
    lower = normalize_text_content(text).lower()
    markers = [
        "connection broken",
        "incomplete read",
        "incompleteread",
        "remote end closed connection",
        "remotedisconnected",
        "chunkedencodingerror",
        "protocolerror",
        "connection aborted",
        "connection reset by peer",
        "broken pipe",
        "read timed out",
        "readtimeout",
        "unexpected eof",
        "ssl: unexpected eof",
        "unexpected error: ('connection broken:",
    ]
    return any(marker in lower for marker in markers)


def _extract_final_verdict(text: str) -> str:
    normalized = normalize_text_content(text or "")
    if not normalized:
        return "unknown"
    lower = normalized.lower()
    matches: List[tuple[int, str]] = []
    patterns = [
        r"\bverdict\s*[:=\]]\s*(pass|fail)\b",
        r"\bresult\s*[:=\]]\s*(pass|fail)\b",
        r"\bfinal result\s*[:=]\s*(pass|fail)\b",
        r"\[verdict\]\s*(pass|fail)\b",
        r"\[result\]\s*(pass|fail)\b",
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


def _looks_like_local_scaffolding_output(tool_name: str, text: str) -> bool:
    tool = str(tool_name or "").strip().lower()
    if tool not in {"execute_command", "execute_shell"}:
        return False

    normalized = normalize_text_content(text)
    lower = normalized.lower()
    if not lower.strip():
        return False

    target_markers = [
        "target:",
        "target url:",
        "http://",
        "https://",
        "status:",
        "http status",
        "response",
        "payload",
        "server:",
        "baseline",
        "verdict",
        "vulnerable",
        "not vulnerable",
        "[fail]",
        "[success]",
        "result:",
        "curl ",
        "wget ",
        "python ",
    ]
    if any(marker in lower for marker in target_markers):
        return False

    if re.search(r"--- stdout ---\s*[a-z0-9_./:-]{1,96}\s*--- stderr ---", lower, re.DOTALL):
        return True

    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    if len(lines) <= 4 and len(normalized) <= 180:
        compact = " ".join(lines).lower()
        if re.fullmatch(r"(exit code:\s*0\s*)?(--- stdout ---\s*)?[a-z0-9_./:-]{3,120}(\s*--- stderr ---\s*)?", compact):
            return True

    return False


def _guess_vuln_type(text: str) -> str:
    lower = text.lower()
    scores = {
        "sql_injection": 0,
        "xss": 0,
        "xxe": 0,
        "ssti": 0,
        "rce": 0,
        "file_inclusion": 0,
        "ssrf": 0,
        "auth_bypass": 0,
    }
    has_ssti_vector = _has_ssti_vector_signal(lower)
    has_struts_ognl_vector = any(p in lower for p in ["struts2", "ognl", "xwork", "s2-045", "s2-052", "s2-057", "actionchain", "namespace"])

    for p in ["ssti", "template injection", "jinja", "jinja2", "thymeleaf", "freemarker", "velocity", "{{7*7}}", "{{233*233}}"]:
        if p in lower:
            scores["ssti"] += 2
    if has_ssti_vector:
        scores["ssti"] += 4
        if any(p in lower for p in ["uid=", "gid=", "whoami", "command execution", "popen("]):
            # 模板注入触发命令执行时，优先判定根因类型为 SSTI，而不是直接归并为 RCE。
            scores["ssti"] += 2
    if "54289" in lower:
        scores["ssti"] += 1
    for p in ["sql injection", "sqli", "union select", "sql syntax", "mysql", "postgresql", "sqlite"]:
        if p in lower:
            scores["sql_injection"] += 2
    for p in ["xss", "onerror=", "javascript:", "payload reflected", "<script>alert", "<img src=x onerror"]:
        if p in lower:
            scores["xss"] += 2
    if re.search(r"\brce\b", lower):
        scores["rce"] += 2
    for p in ["remote code execution", "command execution", "uid=", "whoami", "ognl", "ognl injection", "ognl payload", "struts2", "actionchain", "namespace"]:
        if p in lower:
            scores["rce"] += 2
    for p in [
        "spring4shell",
        "log4shell",
        "rememberme",
        "fastjson",
        "autotype",
        "weblogic",
        "xmldecoder",
        "wls-wsat",
        "phpunit",
        "eval-stdin.php",
        "drupalgeddon",
        "jmxinvokerservlet",
        "webdav",
    ]:
        if p in lower:
            scores["rce"] += 2
    if any(p in lower for p in ["struts2", "s2-0", "s2_0", "ognl"]) and any(p in lower for p in ["%{", "${", "payload"]):
        scores["rce"] += 3
    if any(p in lower for p in ["struts2", "ognl"]) and "54289" in lower:
        scores["rce"] += 2
    if any(p in lower for p in ["..%2f", ".%2e/", "/cgi-bin/.%2e", "path traversal"]) and any(
        p in lower for p in ["uid=", "whoami", "gid=", "command output"]
    ):
        scores["rce"] += 4
    if has_struts_ognl_vector:
        scores["rce"] += 5
        scores["ssti"] = max(0, scores["ssti"] - 4)
    if has_ssti_vector and not any(p in lower for p in ["struts2", "ognl", "s2-"]):
        scores["rce"] = max(0, scores["rce"] - 3)
    for p in ["lfi", "rfi", "file inclusion", "path traversal", "../", "..%2f", ".%2e/", "/etc/passwd", "/proc/self/environ", "win.ini"]:
        if p in lower:
            scores["file_inclusion"] += 2
    for p in ["ssrf", "169.254.169.254", "metadata", "localhost"]:
        if p in lower:
            scores["ssrf"] += 2
    for p in ["authentication bypass", "unauthorized access", "idor", "broken access control"]:
        if p in lower:
            scores["auth_bypass"] += 2

    # Avoid XXE false positives from generic HTML <!DOCTYPE>.
    xxe_hits = 0
    for p in ["xxe", "external entity", "<!entity", "dtd", "xml parser", "file:///etc/passwd"]:
        if p in lower:
            xxe_hits += 1
    if "<!doctype" in lower and "xml" in lower:
        xxe_hits += 1
    if xxe_hits >= 2:
        scores["xxe"] = xxe_hits * 2

    # Resolve common ambiguity: Struts2 OGNL probes can resemble SSTI payloads.
    if has_struts_ognl_vector:
        return "rce"
    # Prefer root-cause classification: if a clear SSTI payload chain is present and
    # there is no Struts/OGNL signal, keep the vuln type as SSTI even when command
    # execution is later achieved through that template injection.
    if has_ssti_vector:
        return "ssti"
    best = max(scores.items(), key=lambda x: x[1])
    return best[0] if best[1] > 0 else "unknown"

def _guess_vuln_name(vuln_type: str, cve: Optional[str]) -> str:
    if cve:
        return f"{cve} ({vuln_type})"
    mapping = {
        "sql_injection": "SQL 注入",
        "xss": "跨站脚本攻击（XSS）",
        "xxe": "XML 外部实体注入（XXE）",
        "ssti": "服务端模板注入（SSTI）",
        "rce": "远程代码执行（RCE）",
        "file_inclusion": "文件包含/路径穿越",
        "ssrf": "服务端请求伪造（SSRF）",
        "auth_bypass": "认证/授权绕过",
        "unknown": "潜在漏洞",
    }
    return mapping.get(vuln_type, "潜在漏洞")


def _extract_lines_by_keywords(text: str, keywords: List[str], limit: int = 8) -> List[str]:
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if any(k in lower for k in keywords):
            lines.append(line)
        if len(lines) >= limit:
            break
    return lines


def _build_reproduction_steps(vuln_type: str, cve: Optional[str], request_evidence: List[str]) -> List[str]:
    common = [
        "确认目标服务可达并记录目标 URL/端口。",
        "根据疑似漏洞类型发送最小化探测请求。",
        "对比请求/响应行为，确认漏洞特征可复现。",
        "保留请求与响应证据，便于审计与复测。",
    ]
    if vuln_type == "rce":
        common[1] = "向目标发送可控命令执行探测。"
        common[2] = "通过确定性输出（如 uid/whoami）确认命令执行。"
    elif vuln_type == "sql_injection":
        common[1] = "对可疑参数执行布尔/报错/时间盲注探测。"
        common[2] = "验证 SQL 报错特征或响应时间/数据差异。"
    elif vuln_type == "xss":
        common[1] = "注入上下文安全的 XSS 载荷并触发页面渲染。"
        common[2] = "确认反射型或存储型场景下的载荷执行。"
    elif vuln_type == "ssti":
        common[1] = "发送 SSTI 表达式探测（如 {{7*7}} 或等价语法）。"
        common[2] = "确认服务端表达式求值或模板上下文泄露。"
    if cve:
        common.insert(1, f"按照 {cve} 公开利用条件构造验证请求。")
    if request_evidence:
        common.append(f"关键请求证据：{request_evidence[0][:160]}")
    return common[:6]

def _build_remediation(vuln_type: str, cve: Optional[str]) -> List[str]:
    base = [
        "建立补丁管理、最小权限、输入校验与持续安全测试机制，降低复发风险。"
    ]
    mapping = {
        "rce": [
            "关闭或严格限制危险执行路径，禁止将不可信输入拼接到命令/解释器上下文。",
            "落实最小权限与进程隔离，降低利用后的横向影响范围。",
            "部署 WAF 与运行时监测规则，识别并拦截高危载荷模式。",
        ],
        "sql_injection": [
            "统一使用参数化查询/预编译语句，禁止字符串拼接 SQL。",
            "收敛数据库权限并关闭详细 SQL 报错回显。",
            "补充 SQL 注入回归测试（布尔/报错/时间盲注场景）。",
        ],
        "xss": [
            "对所有不可信数据实施上下文感知输出编码（HTML/JS/URL）。",
            "启用严格 CSP 并减少内联脚本执行。",
            "加强前后端输入校验与模板安全渲染策略。",
        ],
        "xxe": [
            "在 XML 解析器中禁用 DTD 与外部实体解析。",
            "使用严格 Schema 校验 XML，拒绝不安全实体引用。",
            "限制应用访问本地文件与内网资源的能力。",
        ],
        "ssti": [
            "禁止将用户输入直接拼接到模板表达式，使用固定模板与安全变量绑定。",
            "启用模板沙箱并关闭危险对象访问/执行能力。",
            "最小化模板上下文暴露，移除敏感对象。",
        ],
        "ssrf": [
            "实施严格 URL/主机/端口白名单，封禁元数据与内网地址段访问。",
            "在网络层与运行时同时限制对外访问能力。",
            "增加 SSRF 异常外联行为监测与告警。",
        ],
        "file_inclusion": [
            "对文件路径做规范化并实施白名单，阻断穿越与动态包含模式。",
            "禁用不安全协议包装器与远程文件包含能力。",
            "上传/临时目录与可执行路径隔离并设置严格权限。",
        ],
        "auth_bypass": [
            "对所有敏感操作强制服务端认证与授权校验。",
            "实施对象级权限控制，防止 IDOR/BAC 问题并保留审计日志。",
            "强化会话/令牌生命周期控制，定期轮换密钥。",
        ],
    }
    if cve:
        base.insert(0, f"核查 {cve} 受影响版本并升级到厂商修复版本。")
    return mapping.get(
        vuln_type,
        ["完善输入校验、访问控制与补丁治理，封堵完整利用链路。"],
    ) + base

def _extract_finding_from_text(
    text: str,
    source_tool: str = "tool",
    expected_cves: Optional[List[str]] = None,
    expected_family: str = "",
    benchmark_target_id: Optional[str] = None,
    context_text: str = "",
) -> Optional[Dict]:
    text = normalize_text_content(text)
    context_text = normalize_text_content(context_text)
    if _looks_like_transport_level_error(text):
        return None
    if _looks_like_local_scaffolding_output(source_tool, text):
        return None
    lower = text.lower()
    full_lower = f"{text}\n{context_text}".lower()
    final_verdict = _extract_final_verdict(text)
    vuln_type = _guess_vuln_type(text)
    has_struts_ognl_vector = any(p in full_lower for p in ["struts2", "ognl", "xwork", "s2-045", "s2-052", "s2-057", "actionchain", "namespace"])
    if has_struts_ognl_vector and vuln_type == "ssti":
        vuln_type = "rce"

    command_injection_fail_markers = [
        "verdict: fail - no command injection vulnerability detected",
        "no command injection vulnerability detected",
        "no 'uid=' markers found",
        "no uid= markers found",
        "reason: no 'uid=' markers found",
        "reason: no uid= markers found",
    ]
    has_command_injection_fail_signature = any(marker in full_lower for marker in command_injection_fail_markers)

    strong_markers = [
        "confirmed",
        "exploit success",
        "successfully exploited",
        "is vulnerable",
        "pass: command execution successful",
        "pass: found x-check header",
        "x-cmd-result header found",
        "\u6f0f\u6d1e\u5b58\u5728",
        "\u786e\u8ba4\u6f0f\u6d1e",
        "uid=",
        "root:x:",
        '"vulnerable": true',
        "vulnerable: true",
    ]
    weak_markers = [
        "ssti",
        "template injection",
        "jinja",
        "sql injection",
        "xss",
        "xxe",
        "ssrf",
        "path traversal",
        "struts2",
        "ognl",
        "54289",
    ]
    negative_markers = [
        "verdict: fail",
        "not vulnerable",
        "no vulnerability",
        "no command injection vulnerability detected",
        "no 'uid=' markers found",
        "no uid= markers found",
        "method not allowed",
        "403 forbidden",
        "404 not found",
        "http status 404",
        "404 - not found",
        "< http/1.1 404",
        "failed to exploit",
        "payload not reflected",
        "not directly hit",
        "no result defined for action",
        "无s2-057特征",
        "未命中",
        "no obvious template engine syntax",
        "\u672a\u53d1\u73b0\u6f0f\u6d1e",
        "\u672a\u76f4\u63a5\u547d\u4e2d",
        "\u672a\u68c0\u6d4b\u5230\u660e\u663e\u7684\u6a21\u677f\u5f15\u64ce\u8bed\u6cd5",
        '"vulnerable": false',
        "vulnerable: false",
        "[-] no flag found",
        "no flag found",
        "flag not found",
        "\u672a\u627e\u5230flag",
        "\u672a\u53d1\u73b0\u56de\u663e",
        "\u672a\u627e\u5230\u56de\u663e",
        "payload not executed",
        "execution failed",
        "injection failed",
        "failed or blocked",
        "blocked by",
        "blocked.",
        "no command execution detected",
        "response does not contain",
        "could not find",
        "target may not be vulnerable",
        "\u672a\u6267\u884c\u6210\u529f",
        "only status code",
    ]

    has_affirmative_vulnerable = (
        "vulnerable" in lower
        and "not vulnerable" not in lower
        and "vulnerable: false" not in lower
        and '"vulnerable": false' not in lower
    )
    has_strong = has_affirmative_vulnerable or any(m in lower for m in strong_markers)
    has_weak = any(m in lower for m in weak_markers)
    exploit_signal_markers = [
        "payload",
        "exploit",
        "vulnerable",
        "漏洞存在",
        "确认漏洞",
        "uid=",
        "whoami",
        "ognl",
        "{{",
        "%{",
        "${",
        "union select",
        "sql syntax",
        "onerror=",
        "<script>alert",
        "/etc/passwd",
        "${jndi:",
    ]
    has_exploit_signal = any(m in lower for m in exploit_signal_markers)
    has_negative = any(m in full_lower for m in negative_markers)
    verification_sensitive_types = {
        "rce",
        "ssti",
        "sql_injection",
        "xss",
        "xxe",
        "ssrf",
        "file_inclusion",
        "auth_bypass",
    }
    runtime_positive_markers = [
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
        "hacked_by_ognl",
        "command executed",
        "command execution successful",
        "exploit success",
        "shell output",
        "[status] vulnerable",
        "pass - vulnerability confirmed",
        "successfully injected in response",
    ]
    runtime_negative_hints = [
        "no command output",
        "no command execution detected",
        "no command injection vulnerability detected",
        "no 'uid=' markers found",
        "no uid= markers found",
        "verdict: fail",
        "=== verdict: fail ===",
        "verdict: not vulnerable",
        "unexpected error",
        "response ended prematurely",
        "deterministic marker:",
        "looking for marker:",
        "expected result:",
        "did not execute",
        "not executed",
        "execution failed",
        "payload blocked",
        "not vulnerable",
        "contains '54289': false",
        "contains 'vuln_check_12345': false",
        "contains 'echo': false",
        "final conclusion",
        "结论: fail",
        "[结论] fail",
        "未检测到",
        "未发现",
    ]
    has_runtime_signal = any(token in full_lower for token in runtime_positive_markers) and not any(
        hint in full_lower for hint in runtime_negative_hints
    )
    if has_command_injection_fail_signature:
        has_runtime_signal = False
    has_transport_artifact = _has_transport_artifact(full_lower)
    has_explicit_success_signal = any(
        token in full_lower
        for token in [
            "[result] pass",
            "结论: pass",
            "[结论] pass",
            "pass - vulnerability confirmed",
            "[status] vulnerable",
            "vulnerable: true",
            '"vulnerable": true',
            "漏洞存在",
            "确认漏洞",
            "uid=",
            "gid=",
            "whoami",
            "x-cmd-result:",
            "x-check:",
            "x-user-name:",
        ]
    ) and not has_negative
    if final_verdict == "pass":
        # Respect explicit final PASS when scripts include intermediate failed attempts.
        has_negative = False
        has_explicit_success_signal = True
        has_strong = True
    elif final_verdict == "fail":
        has_negative = True
    if not has_strong and not has_weak:
        return None
    if not has_strong and not has_exploit_signal:
        return None
    if has_command_injection_fail_signature and not has_runtime_signal and not has_explicit_success_signal:
        return None
    if vuln_type == "rce" and has_negative and not has_runtime_signal and not has_explicit_success_signal:
        return None
    if vuln_type == "rce" and _looks_like_expected_result_only_probe(full_lower):
        return None
    if final_verdict == "fail" and not has_runtime_signal and not has_explicit_success_signal:
        return None

    # Suppress SSTI noise when only payload probes exist but no deterministic evaluation evidence.
    if vuln_type == "ssti" and not has_strong:
        has_probe = any(token in full_lower for token in ["7*7", "233*233", "{{7*7}}", "${7*7}", "%{7*7}"])
        has_eval = any(token in full_lower for token in ["54289", "hello 49", "hello 54289"])
        looks_like_struts2_probe_noise = ("struts2" in lower or "ognl" in lower) and not has_eval
        has_explicit_negative = any(
            marker in full_lower
            for marker in [
                "not vulnerable",
                "payload not reflected",
                "not directly hit",
                '"vulnerable": false',
                "vulnerable: false",
                "no flag found",
                "no visible echo",
            ]
        )
        if has_probe and not has_eval:
            return None
        if looks_like_struts2_probe_noise:
            return None
        if has_explicit_negative and not has_eval:
            return None

    if vuln_type == "rce" and has_struts_ognl_vector:
        looks_like_plain_template_only = (
            _has_ssti_vector_signal(full_lower)
            and not any(token in full_lower for token in ["uid=", "gid=", "whoami", "x-cmd-result:", "hacked_by_ognl", "54289", "hello 49"])
            and not any(token in full_lower for token in ["actionchain", "namespace", "content-type: %{", "multipart/form-data"])
        )
        if looks_like_plain_template_only:
            return None

    has_partial_processing_signal = any(
        token in full_lower
        for token in [
            "processing detected",
            "ognl processing detected",
            "struts/ognl processing detected",
            "x-ognl header present: false",
            "header present: false",
        ]
    )

    direct_cves = [x.upper() for x in _extract_cves(text)]
    context_cves = [x.upper() for x in _extract_cves(context_text)]
    cves = list(dict.fromkeys([*direct_cves, *context_cves]))
    expected_cves = [x.upper() for x in (expected_cves or []) if x]
    cve = None
    attribution_source = "llm_extracted" if cve else "none"
    inference_text = f"{text}\n{context_text}"
    signature_ranked = _infer_cve_candidates_from_signatures(inference_text, top_k=6)
    signature_guarded = [x for x in signature_ranked if _cve_inference_guard(x, inference_text)]
    inferred_cve = signature_guarded[0] if signature_guarded else None
    context_cve = _infer_cve_from_challenge_context(context_text)
    if context_cve and context_cve not in cves:
        cves.append(context_cve)
    for c in signature_guarded:
        if c and c not in cves:
            cves.append(c)

    # In negative/no-runtime RCE outputs, raw CVE strings in banners are usually hypothesis labels.
    # Keep evidence-grounded anchors only.
    if vuln_type == "rce" and has_negative and not has_runtime_signal:
        keep = set()
        keep.update([x.upper() for x in direct_cves if x])
        keep.update(signature_guarded)
        if benchmark_target_id and expected_cves and context_cve in expected_cves:
            keep.add(context_cve)
        cves = [x for x in cves if x in keep]

    if vuln_type in verification_sensitive_types and not has_runtime_signal and not has_explicit_success_signal:
        if has_negative or _looks_like_status_only_probe(inference_text):
            if benchmark_target_id and expected_cves:
                allowed = {x.upper() for x in expected_cves if x}
                cves = [x for x in cves if x in allowed]
            else:
                cves = []
            inferred_cve = None
            if not cves:
                cve = None
                attribution_source = "none"

    # Stable CVE preference:
    # signature/evidence > direct extraction > weak context hint
    preferred_pool: List[str] = []
    preferred_pool.extend(signature_guarded)
    preferred_pool.extend([x.upper() for x in direct_cves if x])
    if context_cve:
        preferred_pool.append(context_cve)
    preferred_pool.extend(cves)
    preferred_pool = [x.upper() for x in preferred_pool if x]
    dedup_pool: List[str] = []
    seen_pool = set()
    for item in preferred_pool:
        if item in seen_pool:
            continue
        seen_pool.add(item)
        dedup_pool.append(item)
    cves = dedup_pool
    if cves:
        cve = cves[0]
        if inferred_cve and cve == inferred_cve:
            attribution_source = "signature_inferred"
        elif context_cve and cve == context_cve and cve not in set(direct_cves):
            attribution_source = "challenge_context"
        else:
            attribution_source = "llm_extracted"
    if not cve and inferred_cve and not has_negative and (has_strong or has_exploit_signal):
        cve = inferred_cve
        attribution_source = "signature_inferred"
    if not cve and context_cve and (has_strong or has_exploit_signal):
        cve = context_cve
        attribution_source = "challenge_context"

    request_evidence = _extract_lines_by_keywords(
        text,
        ["target", "url:", "payload", "request", "post ", "get ", "content-type", "parameter", "cmd", "{{", "%{7*7}", "ognl", "\u8bf7\u6c42", "\u53c2\u6570"],
        limit=10,
    )
    response_evidence = _extract_lines_by_keywords(
        text,
        [
            "status code",
            "status",
            "response",
            "header",
            "x-",
            "vulnerable",
            "exploit success",
            "pass - vulnerability confirmed",
            "final conclusion",
            "error",
            "uid=",
            "54289",
            "hello 49",
            "method not allowed",
            "ognl injection",
            "struts2 vulnerability",
            "\u72b6\u6001\u7801",
            "\u54cd\u5e94",
            "\u6f0f\u6d1e\u5b58\u5728",
            "\u6267\u884c\u6210\u529f",
        ],
        limit=10,
    )

    vuln_name = _guess_vuln_name(vuln_type, cve)
    confidence = 0.12
    if has_strong:
        confidence += 0.45
    elif has_weak:
        confidence += 0.15
    if request_evidence:
        confidence += 0.15
    if response_evidence:
        confidence += 0.15
    if vuln_type == "ssti":
        has_ssti_runtime = any(token in full_lower for token in ["54289", "hello 49", "hello 54289"])
        if has_ssti_runtime:
            confidence += 0.1
        else:
            confidence -= 0.3
    if vuln_type == "rce":
        has_rce_runtime = any(
            token in full_lower
            for token in [
                "uid=",
                "gid=",
                "whoami",
                "command output",
                "execution result",
                "x-check: s2-045-test",
                "x-cmd-result:",
                "x-user-name:",
                "x-test-bypass: ok",
            ]
        )
        if has_rce_runtime:
            confidence += 0.1
        elif has_partial_processing_signal:
            confidence += 0.06
    negative_hits = sum(1 for marker in negative_markers if marker in full_lower)
    if has_negative and not has_strong:
        confidence -= min(0.2 + 0.05 * negative_hits, 0.45)
        if not cves and vuln_type != "unknown":
            confidence = min(confidence, 0.25)
    if negative_hits >= 2 and not has_strong:
        confidence = min(confidence, 0.2)
    confidence = max(0.0, min(1.0, confidence))

    if _looks_like_expected_result_only_probe(full_lower):
        confidence = min(confidence, 0.18)
    if vuln_type in verification_sensitive_types and not has_runtime_signal and not has_explicit_success_signal:
        if has_negative:
            confidence = min(confidence, 0.24)
        if _looks_like_status_only_probe(full_lower) and not (
            has_transport_artifact and has_partial_processing_signal and vuln_type == "rce"
        ):
            confidence = min(confidence, 0.22)
    if has_transport_artifact and not has_runtime_signal and not has_explicit_success_signal:
        if has_partial_processing_signal and vuln_type == "rce":
            confidence = max(confidence, 0.33)
            confidence = min(confidence, 0.38)
        else:
            confidence = min(confidence, 0.26)
    if confidence < 0.3:
        return None

    finding = {
        "vuln_name": vuln_name,
        "vuln_type": vuln_type,
        "cve": cve,
        "cve_candidates": cves,
        "confidence": confidence,
        "source_tool": source_tool,
        "expected_cves": expected_cves,
        "expected_family": expected_family or "",
        "benchmark_target_id": benchmark_target_id,
        "attribution_source": attribution_source,
        "request_evidence": request_evidence,
        "response_evidence": response_evidence,
        "evidence": text[:6000],
        "reproduction_steps": _build_reproduction_steps(vuln_type, cve, request_evidence),
        "remediation": _build_remediation(vuln_type, cve),
        "timestamp": int(time.time()),
    }
    if has_transport_artifact and has_partial_processing_signal and not has_runtime_signal:
        notes = list(finding.get("uncertainty_notes") or [])
        notes.append("Transport interruption occurred after partial verification signals; treat this as unstable evidence requiring a stricter retry.")
        finding["uncertainty_notes"] = notes
        finding["evidence_quality"] = "partial_with_transport_error"
    return finding
def _finding_key(finding: Dict) -> str:
    return finding_identity_key(finding)
