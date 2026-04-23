import os
import re
from typing import Dict, List, Optional, Tuple

from shell_agent.rag.retriever import retrieve_cve_records


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_FAMILY_ALIASES = {
    "struts2": ["struts", "struts2", "ognl", "xwork", "s2-045", "s2-052", "s2-057"],
    "tomcat": ["tomcat", "jsp", "webdav"],
    "weblogic": ["weblogic", "wls-wsat", "t3"],
    "spring": ["spring", "springboot", "spring4shell"],
    "shiro": ["shiro", "rememberme"],
    "fastjson": ["fastjson", "autotype"],
    "log4j": ["log4j", "log4shell", "jndi"],
    "jboss": ["jboss", "wildfly"],
    "jenkins": ["jenkins", "groovy", "script console"],
    "confluence": ["confluence", "atlassian"],
    "exchange": ["exchange", "proxylogon", "owa"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch", "elastic", "_cat"],
    "apache": ["apache", "httpd", "path traversal", "..%2f", ".%2e/"],
    "flask": ["flask", "jinja", "jinja2", "render_template"],
    "php": ["php", "phpunit", "eval-stdin.php"],
    "drupal": ["drupal", "drupalgeddon"],
    "wordpress": ["wordpress", "wp-content", "wp-json"],
    "joomla": ["joomla"],
}

_VECTOR_MARKERS = [
    "content-type",
    "multipart/form-data",
    "ognl",
    "actionchain",
    "namespace",
    "doupload.action",
    "application/xml",
    "xstream",
    "wls-wsat",
    "webdav",
    "put /",
    ".jsp",
    "rememberme",
    "autotype",
    "jndi",
    "class.module.classloader",
    "..%2f",
    ".%2e/",
    "/etc/passwd",
    "uid=",
    "whoami",
    "root:x:",
    "54289",
    "hello 49",
]


def _normalize_text(text: str) -> str:
    value = str(text or "").lower()
    value = value.replace("–", "-").replace("—", "-").replace("：", ":")
    return re.sub(r"\s+", " ", value).strip()


def _normalize_cve(cve: Optional[str]) -> Optional[str]:
    value = str(cve or "").strip().upper()
    if not value:
        return None
    return value if _CVE_RE.fullmatch(value) else None


def _merge_unique(items: List[str], limit: int = 20) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        normalized = str(item or "").strip()
        if not normalized:
            continue
        key = normalized.upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized.upper() if key.startswith("CVE-") else normalized)
        if len(out) >= limit:
            break
    return out


def _extract_cves(text: str) -> List[str]:
    return _merge_unique([x.upper() for x in _CVE_RE.findall(str(text or ""))], limit=16)


def _infer_product_family(text: str, primary_template: Optional[Dict]) -> str:
    primary_products = list((primary_template or {}).get("products") or [])
    if primary_products:
        first = str(primary_products[0] or "").strip().lower()
        if first:
            return first

    lower = _normalize_text(text)
    for family, aliases in _FAMILY_ALIASES.items():
        if any(alias in lower for alias in aliases):
            return family
    return "unknown"


def _record_vuln_type(record: Dict) -> str:
    declared = str(record.get("type") or "").strip().lower()
    if declared:
        return declared
    lower = _normalize_text(
        " ".join(
            [
                str(record.get("description") or ""),
                str(record.get("default_probe") or ""),
                " ".join(str(x) for x in (record.get("fingerprint_keywords") or [])),
            ]
        )
    )
    if any(token in lower for token in ["sql injection", "sqli", "union select", "database error"]):
        return "sql_injection"
    if any(token in lower for token in ["xss", "cross-site scripting", "onerror=", "<script"]):
        return "xss"
    if any(token in lower for token in ["ssrf", "metadata", "server-side request forgery"]):
        return "ssrf"
    if any(token in lower for token in ["xxe", "xml external entity", "<!entity"]):
        return "xxe"
    if any(token in lower for token in ["path traversal", "file inclusion", "/etc/passwd", "lfi"]):
        return "file_inclusion"
    if any(token in lower for token in ["template injection", "ssti", "jinja", "twig", "freemarker"]):
        return "ssti"
    if any(token in lower for token in ["auth bypass", "unauthorized", "rememberme", "bypass"]):
        return "auth_bypass"
    if any(token in lower for token in ["rce", "remote code execution", "command execution", "ognl", "deserialization"]):
        return "rce"
    return "unknown"


def _extract_vector_terms(text: str, primary_template: Optional[Dict], limit: int) -> List[str]:
    lower = _normalize_text(text)
    terms: List[str] = []
    for marker in _VECTOR_MARKERS:
        if marker in lower:
            terms.append(marker)
    for marker in list((primary_template or {}).get("confirm_markers") or [])[:10]:
        token = _normalize_text(str(marker))
        if token and token in lower:
            terms.append(token)
    return _merge_unique(terms, limit=max(2, limit))


def _derive_vector_aliases(family: str, text: str) -> List[str]:
    lower = _normalize_text(text)
    aliases: List[str] = []

    if family == "struts2":
        if any(token in lower for token in ["s2-045", "s2_045", "s2-046", "s2_046"]):
            aliases.extend(["s2-045", "cve-2017-5638"])
        if "content-type" in lower and "multipart/form-data" in lower:
            aliases.extend(["s2-045", "cve-2017-5638"])
        if "actionchain" in lower or "namespace" in lower:
            aliases.extend(["s2-057", "cve-2018-11776"])
        if "application/xml" in lower or "xstream" in lower:
            aliases.extend(["s2-052", "cve-2017-9805"])
    elif family == "tomcat":
        if "put /" in lower or "webdav" in lower or ".jsp" in lower:
            aliases.extend(["cve-2017-12615"])
    elif family == "apache":
        if "..%2f" in lower or ".%2e/" in lower or "/cgi-bin/.%2e" in lower:
            aliases.extend(["cve-2021-41773"])

    return _merge_unique(aliases, limit=6)


def _has_runtime_anchor(text: str) -> bool:
    lower = _normalize_text(text)
    if any(token in lower for token in ["uid=", "gid=", "whoami", "root:x:", "hacked_by_ognl"]):
        return True
    header_like = any(
        token in lower
        for token in [
            "cmd-output:",
            "x-command-output:",
            "x-cmd-result:",
            "x-ognl-verify",
            "deterministic evidence of ognl expression execution",
        ]
    )
    negative_context = any(
        token in lower
        for token in ["not found", "no command output", "missing", "not vulnerable", "[fail]", "fail -"]
    )
    return header_like and not negative_context


def _build_vector_alias_candidates(
    profile: Dict,
    vector_aliases: List[str],
    intel_index: Dict[str, Dict],
    limit: int,
) -> List[Dict]:
    rows: List[Dict] = []
    family = str(profile.get("product_family") or "unknown").strip().lower()
    vuln_type = str(profile.get("vuln_type") or "unknown").strip().lower()
    seen = set()
    for token in vector_aliases or []:
        cve_id = _normalize_cve(token)
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        record = dict((intel_index or {}).get(cve_id) or {})
        record_family = str(record.get("product_family") or family or "unknown").strip().lower()
        record_type = _record_vuln_type(record) if record else vuln_type or "unknown"
        score = 0.88
        reasons = ["vector_alias"]
        if vuln_type != "unknown" and record_type == vuln_type:
            score += 0.06
            reasons.append("type_match")
        if family != "unknown" and record_family == family:
            score += 0.04
            reasons.append("family_match")
        rows.append(
            {
                "cve": cve_id,
                "score": round(max(0.0, min(1.0, score)), 4),
                "source": "vector_alias",
                "product_family": record_family,
                "record_vuln_type": record_type,
                "reasons": reasons,
                "record": record,
            }
        )
    rows.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return rows[: max(1, limit)]


def _allow_family_expansion(profile: Dict) -> bool:
    family = str(profile.get("product_family") or "unknown").strip().lower()
    explicit_cve = _normalize_cve(profile.get("explicit_cve"))
    direct_cves = [_normalize_cve(x) for x in (profile.get("direct_cves") or [])]
    direct_cves = [x for x in direct_cves if x]
    vector_terms = [str(x).strip().lower() for x in (profile.get("vector_terms") or []) if str(x).strip()]
    combined = str(profile.get("raw_text") or "")
    lower = _normalize_text(combined)

    if explicit_cve or direct_cves:
        return True
    if _has_runtime_anchor(combined):
        return True

    if family == "struts2":
        struts_specific = [
            "s2-045",
            "cve-2017-5638",
            "invalid content type",
            "multipartrequestwrapper",
            "jakarta",
        ]
        return any(token in lower for token in struts_specific)

    return len(vector_terms) >= 4


def _token_hit_count(text: str, tokens: List[str]) -> int:
    lower = _normalize_text(text)
    return sum(1 for token in (tokens or []) if token and str(token).lower() in lower)


def _record_text(record: Dict) -> str:
    return _normalize_text(
        "\n".join(
            [
                str(record.get("description") or ""),
                str(record.get("default_probe") or ""),
                str(record.get("product_family") or ""),
                str(record.get("raw") or ""),
                " ".join(str(x) for x in (record.get("prerequisites") or [])),
                " ".join(str(x) for x in (record.get("references") or [])),
                " ".join(str(x) for x in (record.get("fingerprint_keywords") or [])),
                " ".join(str(x) for x in (record.get("confirm_markers") or [])),
            ]
        )
    )


def _score_record(
    cve_id: str,
    record: Dict,
    profile: Dict,
    source: str,
) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    family = str(record.get("product_family") or "unknown").strip().lower()
    record_type = _record_vuln_type(record)
    record_text = _record_text(record)
    source_tokens = {
        str(item).strip().lower()
        for item in str(record.get("source") or "").split(",")
        if str(item).strip()
    }
    description = str(record.get("description") or "").strip().lower()

    direct_cves = set(profile.get("direct_cves") or [])
    explicit_cve = _normalize_cve(profile.get("explicit_cve"))
    if explicit_cve and cve_id == explicit_cve:
        score += 0.80
        reasons.append("explicit_cve")
    elif cve_id in direct_cves:
        score += 0.58
        reasons.append("direct_signal")

    profile_family = str(profile.get("product_family") or "unknown").strip().lower()
    if profile_family != "unknown" and family == profile_family:
        score += 0.32
        reasons.append("family_match")
    elif profile_family != "unknown" and family != "unknown":
        if profile_family in family or family in profile_family:
            score += 0.24
            reasons.append("family_near_match")
        else:
            score -= 0.10
            reasons.append("family_mismatch")

    profile_type = str(profile.get("vuln_type") or "unknown").strip().lower()
    if profile_type != "unknown" and record_type == profile_type:
        score += 0.22
        reasons.append("type_match")
    elif profile_type != "unknown" and record_type != "unknown" and record_type != profile_type:
        score -= 0.12
        reasons.append("type_mismatch")

    vector_terms = list(profile.get("vector_terms") or [])
    vector_hits = _token_hit_count(record_text, vector_terms)
    if vector_hits:
        vector_bonus = min(0.26, 0.06 * vector_hits)
        score += vector_bonus
        reasons.append(f"vector_hits={vector_hits}")

    evidence_terms = list(profile.get("evidence_terms") or [])
    evidence_hits = _token_hit_count(record_text, evidence_terms)
    if evidence_hits:
        evidence_bonus = min(0.18, 0.03 * evidence_hits)
        score += evidence_bonus
        reasons.append(f"evidence_hits={evidence_hits}")

    if profile_family != "unknown" and profile_family in record_text:
        score += 0.06
        reasons.append("family_text_support")

    if record.get("default_probe"):
        score += 0.03
        reasons.append("has_probe")
    if record.get("references"):
        score += 0.02
        reasons.append("has_reference")
    if str(record.get("severity") or "").strip().lower() in {"critical", "high"}:
        score += 0.02
        reasons.append("high_severity")
    if "benchmark_seed" in source_tokens:
        score += 0.05
        reasons.append("benchmark_curated")
    if "mainstream_seed" in source_tokens:
        score += 0.04
        reasons.append("mainstream_curated")
    if "vulhub_seed" in source_tokens and source_tokens.issubset({"vulhub_seed"}):
        score -= 0.04
        reasons.append("vulhub_only_noise_penalty")
    if description.startswith("vulhub target seed:") or description.startswith("benchmark seed target:"):
        score -= 0.03
        reasons.append("seed_description_penalty")

    if source == "rag":
        score -= 0.03
        reasons.append("rag_fallback")

    return max(0.0, min(1.0, score)), reasons


def _select_local_candidates(profile: Dict, intel_index: Dict[str, Dict], limit: int) -> List[Dict]:
    rows: List[Dict] = []
    min_score = float(os.getenv("CVE_LOCAL_MIN_SCORE", "0.26"))
    allow_family_expansion = _allow_family_expansion(profile)

    for cve_id, record in (intel_index or {}).items():
        normalized = _normalize_cve(cve_id)
        if not normalized or not isinstance(record, dict):
            continue
        score, reasons = _score_record(normalized, record, profile, source="local")
        if not allow_family_expansion and normalized not in set(profile.get("direct_cves") or []):
            continue
        if score < min_score and normalized not in set(profile.get("direct_cves") or []):
            continue
        rows.append(
            {
                "cve": normalized,
                "score": round(score, 4),
                "source": "local_intel",
                "product_family": str(record.get("product_family") or "unknown").strip().lower(),
                "record_vuln_type": _record_vuln_type(record),
                "reasons": reasons,
                "record": record,
            }
        )

    rows.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return rows[: max(1, limit)]


def _should_query_rag(profile: Dict, local_candidates: List[Dict]) -> bool:
    if os.getenv("ENABLE_CVE_RAG_MATCHING", "true").strip().lower() != "true":
        return False
    if not profile.get("query"):
        return False
    if profile.get("vuln_type") in {"", "unknown"}:
        return False
    if len(local_candidates) >= int(os.getenv("CVE_RAG_TRIGGER_MAX_LOCAL", "2")):
        best = max(float(row.get("score") or 0.0) for row in local_candidates)
        if best >= float(os.getenv("CVE_RAG_SKIP_LOCAL_SCORE", "0.72")):
            return False
        sorted_scores = sorted((float(row.get("score") or 0.0) for row in local_candidates), reverse=True)
        if len(sorted_scores) >= 2 and (sorted_scores[0] - sorted_scores[1]) <= float(os.getenv("CVE_RAG_MARGIN_TRIGGER", "0.08")):
            return True
    return True


def _select_rag_candidates(profile: Dict, local_candidates: List[Dict], limit: int) -> List[Dict]:
    if not _should_query_rag(profile, local_candidates):
        return []

    top_k = max(1, min(limit, int(os.getenv("CVE_RAG_TOP_K", "4"))))
    min_severity = os.getenv("CVE_RAG_MIN_SEVERITY", "medium").strip().lower() or "medium"
    results = retrieve_cve_records(profile["query"], top_k=top_k, min_severity=min_severity)

    rows: List[Dict] = []
    for record in results:
        cve_id = _normalize_cve(record.get("id") or record.get("cve_id"))
        if not cve_id:
            continue
        score, reasons = _score_record(cve_id, record, profile, source="rag")
        rows.append(
            {
                "cve": cve_id,
                "score": round(score, 4),
                "source": "rag_index",
                "product_family": str(record.get("product_family") or "unknown").strip().lower(),
                "record_vuln_type": _record_vuln_type(record),
                "reasons": reasons,
                "record": record,
            }
        )

    rows.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return rows[:top_k]


def _merge_candidate_rows(local_rows: List[Dict], rag_rows: List[Dict], total_limit: int) -> List[Dict]:
    merged: Dict[str, Dict] = {}
    for row in list(local_rows or []) + list(rag_rows or []):
        cve = _normalize_cve(row.get("cve"))
        if not cve:
            continue
        existing = merged.get(cve)
        if not existing or float(row.get("score") or 0.0) > float(existing.get("score") or 0.0):
            merged[cve] = dict(row)
        elif existing:
            existing["source"] = ",".join(
                sorted(set(str(existing.get("source") or "").split(",") + str(row.get("source") or "").split(",")))
            ).strip(",")
            existing["reasons"] = _merge_unique(list(existing.get("reasons") or []) + list(row.get("reasons") or []), limit=12)

    ranked = sorted(merged.values(), key=lambda item: float(item.get("score") or 0.0), reverse=True)
    return ranked[: max(1, total_limit)]


def build_cve_match_plan(
    finding: Dict,
    evidence: str,
    req_evidence: str,
    primary_template: Optional[Dict],
    intel_index: Dict[str, Dict],
) -> Dict:
    combined = "\n".join([str(req_evidence or ""), str(evidence or "")]).strip()
    direct_cves = _merge_unique(
        [
            str(finding.get("cve") or "").upper(),
            *[str(x).upper() for x in (finding.get("cve_candidates") or [])],
            *_extract_cves(combined),
        ],
        limit=12,
    )

    profile = {
        "vuln_type": str(finding.get("vuln_type") or "unknown").strip().lower() or "unknown",
        "explicit_cve": _normalize_cve(finding.get("cve")),
        "direct_cves": [x for x in direct_cves if _normalize_cve(x)],
        "product_family": _infer_product_family(combined, primary_template),
        "vector_terms": _extract_vector_terms(
            combined,
            primary_template=primary_template,
            limit=int(os.getenv("CVE_MATCH_VECTOR_TERM_LIMIT", "8")),
        ),
        "evidence_terms": _extract_vector_terms(combined, primary_template=primary_template, limit=14),
        "query": "",
        "raw_text": combined,
    }
    vector_aliases = _derive_vector_aliases(profile["product_family"], combined)
    profile["vector_terms"] = _merge_unique(profile["vector_terms"] + vector_aliases, limit=12)
    profile["evidence_terms"] = _merge_unique(profile["evidence_terms"] + vector_aliases, limit=18)

    query_parts: List[str] = []
    if profile["vuln_type"] != "unknown":
        query_parts.append(profile["vuln_type"])
    if profile["product_family"] != "unknown":
        query_parts.append(profile["product_family"])
    query_parts.extend(profile["direct_cves"])
    query_parts.extend(profile["vector_terms"][:6])
    query_parts.extend(profile["evidence_terms"][:8])
    profile["query"] = " ".join([part for part in query_parts if part])[:1600]

    local_limit = max(1, int(os.getenv("CVE_LOCAL_CANDIDATE_LIMIT", "6")))
    total_limit = max(1, int(os.getenv("CVE_TOTAL_CANDIDATE_LIMIT", "8")))
    local_candidates = _select_local_candidates(profile, intel_index=intel_index, limit=local_limit)
    alias_candidates = _build_vector_alias_candidates(
        profile=profile,
        vector_aliases=vector_aliases,
        intel_index=intel_index,
        limit=min(total_limit, 4),
    )

    rag_candidates: List[Dict] = []
    if _should_query_rag(profile, local_candidates):
        rag_candidates = _select_rag_candidates(
            profile,
            local_candidates=local_candidates,
            limit=min(total_limit, int(os.getenv("CVE_RAG_TOP_K", "4"))),
        )

    merged = _merge_candidate_rows(local_candidates + alias_candidates, rag_candidates, total_limit=total_limit)
    return {
        "profile": profile,
        "candidates": merged,
        "query": profile["query"],
        "used_rag": bool(rag_candidates),
    }
