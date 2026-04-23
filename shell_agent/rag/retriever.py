"""漏洞案例 RAG 检索器，支持 WooYun 历史案例与 CVE 情报混合检索。"""

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

DATA_DIR = Path(__file__).parent / "data"

VULN_KEYWORDS = {
    "sqli": ["sql", "注入", "injection", "mysql", "oracle", "mssql", "sqlite", "union", "select", "database"],
    "xss": ["xss", "跨站", "script", "alert", "javascript", "dom", "反射", "存储"],
    "rce": ["rce", "命令执行", "command", "exec", "system", "shell", "反序列化", "deserialize", "ognl", "jndi"],
    "ssrf": ["ssrf", "服务端请求", "内网", "127.0.0.1", "localhost", "gopher", "dict", "metadata"],
    "upload": ["上传", "upload", "文件上传", "webshell", "木马", "getshell"],
    "lfi": ["文件包含", "include", "traversal", "目录遍历", "../", "读取文件", "任意文件", "path traversal"],
    "xxe": ["xxe", "xml", "实体", "entity", "dtd"],
    "auth": ["未授权", "越权", "认证", "绕过", "bypass", "权限", "unauthorized"],
    "csrf": ["csrf", "跨站请求", "伪造"],
    "ssti": ["ssti", "模板注入", "template", "jinja", "freemarker", "velocity"],
}

LOW_SIGNAL_TOKENS = {
    "http",
    "https",
    "www",
    "com",
    "target",
    "port",
    "url",
    "host",
    "request",
    "response",
}

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "unknown": 0,
}

MAINSTREAM_FAMILIES = {
    "struts2",
    "log4j",
    "spring",
    "shiro",
    "fastjson",
    "weblogic",
    "tomcat",
    "confluence",
    "exchange",
    "jenkins",
    "redis",
    "elasticsearch",
}

MOJIBAKE_MARKERS = ("锛", "銆", "鍙", "妫", "璇", "鏃", "鍑", "鏈", "绔", "缁")


def _sanitize_text(text: str) -> str:
    value = str(text or "")
    if "\ufffd" in value:
        value = value.replace("\ufffd", "")
    value = re.sub(r"[ \t]{2,}", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def _looks_like_mojibake(text: str) -> bool:
    value = str(text or "")
    if not value:
        return False
    hits = sum(value.count(marker) for marker in MOJIBAKE_MARKERS)
    return hits >= 4


def _readable_text(text: str, max_chars: int = 0) -> str:
    value = _sanitize_text(text)
    if _looks_like_mojibake(value):
        return ""
    if max_chars > 0:
        return value[:max_chars]
    return value


def _sanitize_record(value):
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, list):
        return [_sanitize_record(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_record(item) for key, item in value.items()}
    return value


def _severity_score(severity: str) -> int:
    return SEVERITY_WEIGHTS.get(str(severity or "unknown").strip().lower(), 0)


def _entry_has_operational_value(entry: Dict) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("is_mainstream"):
        return True
    if entry.get("default_probe"):
        return True
    if entry.get("confirm_markers"):
        return True
    if entry.get("poc_available"):
        return True
    family = str(entry.get("product_family") or "").strip().lower()
    if family and family != "unknown":
        return True
    refs = list(entry.get("references") or [])
    return bool(refs)


def _passes_min_severity(entry: Dict, min_sev_score: Optional[int]) -> bool:
    if min_sev_score is None:
        return True
    entry_score = _severity_score(entry.get("severity"))
    if entry_score >= min_sev_score:
        return True
    # Many curated CVE seeds are severity=unknown but still contain high-value probe markers.
    # Keep them when severity threshold is not stricter than medium.
    if (
        entry_score == SEVERITY_WEIGHTS["unknown"]
        and min_sev_score <= SEVERITY_WEIGHTS["medium"]
        and _entry_has_operational_value(entry)
    ):
        return True
    return False


def _extract_cve_tokens(text: str) -> set[str]:
    return {item.upper() for item in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", str(text or ""), re.IGNORECASE)}


def _is_specific_signal(word: str) -> bool:
    token = str(word or "").strip().lower()
    if len(token) < 4:
        return False
    return bool(re.search(r"[\d-]", token))


def _rank_query_words(words: Iterable[str]) -> List[str]:
    def key(token: str) -> Tuple[int, int, int, str]:
        lower = str(token or "").lower()
        is_cve = 1 if lower.startswith("cve-") else 0
        has_digits = 1 if re.search(r"\d", lower) else 0
        is_family = 1 if lower in MAINSTREAM_FAMILIES or lower in {"struts2", "ognl", "actionchain", "weblogic", "fastjson"} else 0
        return (is_cve, has_digits + is_family, len(lower), lower)

    ranked = sorted({str(w).lower() for w in words if str(w).strip()}, key=key, reverse=True)
    return ranked[:18]


def _query_vector_boost(cve_id: str, query_text: str) -> float:
    lower = str(query_text or "").lower()
    if not lower:
        return 0.0
    boost = 0.0
    normalized = str(cve_id or "").strip().upper()

    # Struts2 vector priors
    if any(token in lower for token in ["struts", "struts2", "ognl"]):
        if any(token in lower for token in ["s2-045", "s2_045", "s2-046", "s2_046", "content-type", "multipart/form-data", "doupload.action"]):
            if normalized == "CVE-2017-5638":
                boost += 45.0
            elif normalized.startswith("CVE-201"):
                boost -= 2.5
        if any(token in lower for token in ["s2-057", "s2_057", "s2-059", "s2_059", "actionchain", "namespace"]):
            if normalized == "CVE-2018-11776":
                boost += 45.0
            elif normalized.startswith("CVE-201"):
                boost -= 2.0
        if any(token in lower for token in ["s2-052", "s2_052", "application/xml", "xstream"]):
            if normalized == "CVE-2017-9805":
                boost += 45.0
            elif normalized.startswith("CVE-201"):
                boost -= 2.0
        if normalized in {"CVE-2017-5638", "CVE-2018-11776", "CVE-2017-9805"}:
            boost += 6.0

    # Log4Shell / JNDI prior
    if any(token in lower for token in ["log4j", "log4shell", "jndi"]):
        if normalized == "CVE-2021-44228":
            boost += 42.0
        elif normalized == "CVE-2021-45046":
            boost += 18.0

    # Spring4Shell prior
    if any(token in lower for token in ["spring4shell", "class.module.classloader", "spring framework", "spring mvc"]):
        if normalized == "CVE-2022-22965":
            boost += 40.0

    # Confluence OGNL prior
    if any(token in lower for token in ["confluence", "atlassian", "ognl"]):
        if normalized in {"CVE-2022-26134", "CVE-2023-22515"}:
            boost += 24.0

    return boost


class VulnRetriever:
    """漏洞案例检索器，兼容旧 WooYun 检索接口。"""

    def __init__(self):
        self.id_map: Dict[str, Dict] = {}
        self.keyword_index: Dict[str, List[str]] = {}
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        if not DATA_DIR.exists():
            return

        id_map_path = DATA_DIR / "id_map.json"
        if id_map_path.exists():
            with open(id_map_path, "r", encoding="utf-8") as f:
                self.id_map = _sanitize_record(json.load(f))

        kw_path = DATA_DIR / "keyword_index.json"
        if kw_path.exists():
            with open(kw_path, "r", encoding="utf-8") as f:
                self.keyword_index = json.load(f)

        self._loaded = True

    def _detect_vuln_type(self, query: str) -> Optional[str]:
        query_lower = query.lower()
        for vuln_type, keywords in VULN_KEYWORDS.items():
            if any(kw in query_lower for kw in keywords):
                return vuln_type
        return None

    def _extract_product_family(self, query: str) -> Optional[str]:
        query_lower = query.lower()
        family_aliases = {
            "struts2": ["struts", "struts2", "s2-", "ognl"],
            "log4j": ["log4j", "log4shell", "jndi"],
            "spring": ["spring", "spring4shell", "springboot"],
            "shiro": ["shiro", "rememberme"],
            "fastjson": ["fastjson", "autotype"],
            "weblogic": ["weblogic", "t3"],
            "tomcat": ["tomcat", "jsp"],
            "confluence": ["confluence", "atlassian"],
            "exchange": ["exchange", "proxylogon", "owa"],
            "jenkins": ["jenkins", "groovy"],
            "redis": ["redis"],
            "elasticsearch": ["elasticsearch", "elastic"],
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "php": ["php", "phpunit"],
            "drupal": ["drupal"],
            "wordpress": ["wordpress", "wp-"],
            "jboss": ["jboss", "wildfly"],
        }
        for family, aliases in family_aliases.items():
            if any(alias in query_lower for alias in aliases):
                return family
        return None

    def _score_entry(
        self,
        entry: Dict,
        query_words: set,
        vuln_type: Optional[str],
        product_family: Optional[str],
    ) -> float:
        score = 0.0
        entry_id = str(entry.get("id") or "")
        is_cve = entry_id.startswith("CVE-")
        entry_family = str(entry.get("product_family") or "").lower()
        entry_text = " ".join(
            [
                str(entry.get("title") or ""),
                str(entry.get("description") or ""),
                str(entry.get("raw") or ""),
                " ".join(str(x) for x in (entry.get("fingerprint_keywords") or [])),
            ]
        ).lower()

        keyword_hits = 0
        for word in query_words:
            if word in self.keyword_index and entry_id in self.keyword_index[word]:
                keyword_hits += 1
                score += 2.0

        if vuln_type and str(entry.get("type") or "") == vuln_type:
            score += 5.0

        if product_family:
            if entry_family == product_family:
                score += 15.0
            elif product_family in entry_family or entry_family in product_family:
                score += 8.0

        for word in query_words:
            if len(word) >= 4 and word in entry_text:
                score += 3.0
                if _is_specific_signal(word):
                    score += 18.0

        query_cves = _extract_cve_tokens(" ".join(query_words))
        if query_cves:
            if entry_id.upper() in query_cves:
                score += 40.0
            elif is_cve:
                score -= 5.0

        title_lower = str(entry.get("title") or "").lower()
        for word in query_words:
            if len(word) >= 4 and word in title_lower:
                score += 5.0

        if is_cve:
            score += _severity_score(entry.get("severity"))
            if entry.get("is_mainstream"):
                score += 10.0
            if entry_family in MAINSTREAM_FAMILIES:
                score += 3.0

            for kw in entry.get("fingerprint_keywords") or []:
                if str(kw).lower() in " ".join(query_words):
                    score += 4.0

            cvss = entry.get("cvss")
            if isinstance(cvss, (int, float)):
                score += float(cvss) / 2.0
            if entry.get("default_probe"):
                score += 1.0
            if entry.get("remediation"):
                score += 0.5
        else:
            poc = str(entry.get("poc") or "").strip()
            if poc and poc not in {"(无详述POC)", "无", ""}:
                score += 2.0
            if entry.get("bypass"):
                score += 1.5

        return score + min(keyword_hits, 12) * 0.1

    def _candidate_ids(self, words: Set[str], product_family: Optional[str], vuln_type: Optional[str]) -> Optional[Set[str]]:
        candidate_ids: Set[str] = set()
        ranked_words = _rank_query_words(words)
        for word in ranked_words:
            ids = self.keyword_index.get(word)
            if not ids:
                continue
            candidate_ids.update(ids[:800] if isinstance(ids, list) else ids)
            if len(candidate_ids) >= 5000:
                break

        if not candidate_ids:
            return None

        narrowed: Set[str] = set()
        for eid in candidate_ids:
            entry = self.id_map.get(eid)
            if not entry:
                continue
            if product_family:
                entry_family = str(entry.get("product_family") or "").lower()
                if product_family != entry_family and product_family not in entry_family and entry_family not in product_family:
                    continue
            if vuln_type and str(entry.get("type") or "").lower() != vuln_type.lower():
                # Keep CVE entries because type metadata may be broader than the query.
                if not str(eid).startswith("CVE-"):
                    continue
            narrowed.add(eid)

        return narrowed or candidate_ids

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        vuln_type: Optional[str] = None,
        product_family: Optional[str] = None,
        prefer_cve: bool = False,
        min_severity: Optional[str] = None,
    ) -> List[Dict]:
        self._load()
        if not self.id_map:
            return []

        query_lower = query.lower()
        words = {
            w
            for w in re.findall(r"[a-zA-Z0-9\-]{3,}|[\u4e00-\u9fa5]{2,}", query_lower)
            if w not in LOW_SIGNAL_TOKENS
        }
        if len(words) < 2:
            return []

        detected_type = vuln_type or self._detect_vuln_type(query)
        detected_family = product_family or self._extract_product_family(query)
        min_sev_score = _severity_score(min_severity) if min_severity else None
        candidate_ids = self._candidate_ids(words, detected_family, detected_type)

        scored_entries: List[Tuple[str, float, Dict]] = []
        iterator = candidate_ids if candidate_ids is not None else self.id_map.keys()
        for eid in iterator:
            entry = self.id_map.get(eid)
            if not entry:
                continue
            if min_sev_score is not None and str(eid).startswith("CVE-"):
                if not _passes_min_severity(entry, min_sev_score):
                    continue

            score = self._score_entry(entry, words, detected_type, detected_family)
            if prefer_cve and str(eid).startswith("CVE-"):
                score += 10.0

            if score > 0:
                scored_entries.append((eid, score, entry))

        scored_entries.sort(key=lambda x: x[1], reverse=True)
        return [entry for _, _, entry in scored_entries[:top_k]]

    def retrieve_cve(self, query: str, top_k: int = 3, min_severity: str = "medium") -> List[Dict]:
        self._load()
        if not self.id_map:
            return []

        words = {
            w
            for w in re.findall(r"[a-zA-Z0-9\-]{3,}|[\u4e00-\u9fa5]{2,}", query.lower())
            if w not in LOW_SIGNAL_TOKENS
        }
        detected_type = self._detect_vuln_type(query)
        detected_family = self._extract_product_family(query)
        min_sev_score = _severity_score(min_severity)
        query_cves = _extract_cve_tokens(query)
        candidate_ids = self._candidate_ids(words, detected_family, detected_type)

        results: List[Tuple[float, Dict]] = []
        iterator = candidate_ids if candidate_ids is not None else self.id_map.keys()
        for eid in iterator:
            entry = self.id_map.get(eid)
            if not entry:
                continue
            if not str(eid).startswith("CVE-"):
                continue
            if str(eid).upper() not in query_cves and not _passes_min_severity(entry, min_sev_score):
                continue
            score = self._score_entry(entry, words, detected_type, detected_family)
            score += _query_vector_boost(str(eid), query)
            if str(eid).upper() in query_cves:
                score += 80.0
            if score > 0:
                results.append((score, entry))

        results.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in results[:top_k]]

    def format_results(self, results: List[Dict], include_probe: bool = True) -> str:
        if not results:
            return ""

        lines = ["## 漏洞案例参考", ""]
        for i, result in enumerate(results, 1):
            entry_id = str(result.get("id") or "Unknown")
            is_cve = entry_id.startswith("CVE-")

            if is_cve:
                severity = str(result.get("severity") or "unknown").upper()
                badge = f" [{severity}]" if severity != "UNKNOWN" else ""
                lines.append(f"### {i}. {entry_id} - {result.get('product_family', 'unknown')}{badge}")
            else:
                lines.append(f"### {i}. [{entry_id}] {result.get('title', 'Unknown')}")

            lines.append(f"- 类型: {_sanitize_text(result.get('type', 'unknown'))}")

            if is_cve:
                if result.get("product_family"):
                    lines.append(f"- 产品: {_sanitize_text(result.get('product_family'))}")
                if result.get("cvss") is not None:
                    lines.append(f"- CVSS: {result.get('cvss')}")
                if result.get("description"):
                    desc = _sanitize_text(result.get("description", ""))
                    lines.append(f"- 描述: {desc[:500]}")
                if include_probe and result.get("default_probe"):
                    lines.append(f"- 检测方法: {_sanitize_text(result.get('default_probe'))}")
                markers = list(result.get("confirm_markers") or [])
                if markers:
                    lines.append(f"- 确认标记: {', '.join(_sanitize_text(x) for x in markers[:5])}")
                remediation = list(result.get("remediation") or [])
                if remediation:
                    lines.append(f"- 修复建议: {_sanitize_text(remediation[0])}")
            else:
                if result.get("poc"):
                    poc = _sanitize_text(result.get("poc", ""))
                    if poc:
                        lines.append(f"- POC 摘要: {poc[:600]}")
                if result.get("bypass"):
                    lines.append(f"- 绕过方式: {_sanitize_text(result.get('bypass'))}")
                if result.get("detail"):
                    detail = _sanitize_text(result.get("detail", ""))
                    lines.append(f"- 详情摘要: {detail[:400]}")

            lines.append("")

        return "\n".join(lines)

    def format_cve_brief(self, results: List[Dict]) -> str:
        if not results:
            return ""
        lines = ["## CVE 快速参考", ""]
        for result in results:
            entry_id = str(result.get("id") or "")
            if not entry_id.startswith("CVE-"):
                continue
            severity = str(result.get("severity") or "?")
            family = str(result.get("product_family") or "?")
            lines.append(f"- {entry_id} [{severity}] ({family})")
            if result.get("default_probe"):
                lines.append(f"  检测: {_sanitize_text(result.get('default_probe'))[:100]}")
        return "\n".join(lines)


    def format_results(self, results: List[Dict], include_probe: bool = True) -> str:  # type: ignore[override]
        if not results:
            return ""

        lines = ["## 漏洞案例参考", ""]
        for i, result in enumerate(results, 1):
            entry_id = str(result.get("id") or "Unknown")
            is_cve = entry_id.startswith("CVE-")

            if is_cve:
                severity = str(result.get("severity") or "unknown").upper()
                badge = f" [{severity}]" if severity != "UNKNOWN" else ""
                lines.append(f"### {i}. {entry_id} - {result.get('product_family', 'unknown')}{badge}")
            else:
                title = _readable_text(result.get("title", ""), 180) or entry_id
                lines.append(f"### {i}. [{entry_id}] {title}")

            vuln_type = _readable_text(result.get("type", "unknown"), 80) or "unknown"
            lines.append(f"- 类型: {vuln_type}")

            if is_cve:
                product_family = _readable_text(result.get("product_family"), 120)
                if product_family:
                    lines.append(f"- 产品: {product_family}")
                if result.get("cvss") is not None:
                    lines.append(f"- CVSS: {result.get('cvss')}")
                desc = _readable_text(result.get("description", ""), 500)
                if desc:
                    lines.append(f"- 描述: {desc}")
                if include_probe:
                    probe = _readable_text(result.get("default_probe"), 220)
                    if probe:
                        lines.append(f"- 检测线索: {probe}")
                markers = [
                    item
                    for item in (_readable_text(x, 80) for x in (result.get("confirm_markers") or [])[:5])
                    if item
                ]
                if markers:
                    lines.append(f"- 确认标记: {', '.join(markers)}")
                remediation = [
                    item
                    for item in (_readable_text(x, 220) for x in (result.get("remediation") or [])[:3])
                    if item
                ]
                if remediation:
                    lines.append(f"- 修复建议: {remediation[0]}")
            else:
                poc = _readable_text(result.get("poc", ""), 600)
                if poc:
                    lines.append(f"- POC 摘要: {poc}")
                bypass = _readable_text(result.get("bypass"), 220)
                if bypass:
                    lines.append(f"- 绕过方式: {bypass}")
                detail = _readable_text(result.get("detail", ""), 400)
                if detail:
                    lines.append(f"- 详情摘要: {detail}")

            lines.append("")

        return "\n".join(lines)

    def format_cve_brief(self, results: List[Dict]) -> str:  # type: ignore[override]
        if not results:
            return ""

        lines = ["## CVE 快速参考", ""]
        for result in results:
            entry_id = str(result.get("id") or "")
            if not entry_id.startswith("CVE-"):
                continue
            severity = str(result.get("severity") or "?")
            family = str(result.get("product_family") or "?")
            lines.append(f"- {entry_id} [{severity}] ({family})")
            probe = _readable_text(result.get("default_probe"), 100)
            if probe:
                lines.append(f"  检测: {probe}")
        return "\n".join(lines)


WooyunRetriever = VulnRetriever

_retriever: Optional[VulnRetriever] = None


def get_retriever() -> VulnRetriever:
    global _retriever
    if _retriever is None:
        _retriever = VulnRetriever()
    _retriever._load()
    return _retriever


@lru_cache(maxsize=1)
def _intel_record_map() -> Dict[str, Dict]:
    from shell_agent.cve.intel import load_cve_intel_records

    out: Dict[str, Dict] = {}
    for record in load_cve_intel_records():
        cve_id = str(record.get("cve_id") or "").strip().upper()
        if cve_id.startswith("CVE-"):
            out[cve_id] = dict(record)
    return out


def _enrich_cve_entry(entry: Optional[Dict]) -> Optional[Dict]:
    if not isinstance(entry, dict):
        return None
    merged = dict(entry)
    cve_id = str(merged.get("id") or merged.get("cve_id") or "").strip().upper()
    intel = _intel_record_map().get(cve_id)
    if not intel:
        return merged
    family = intel.get("product_family") or intel.get("family")
    description = intel.get("description")
    source = intel.get("source")
    references = intel.get("references")
    if family:
        merged["family"] = family
        merged["product_family"] = family
    if source:
        merged["intel_source"] = source
    if references:
        merged["references"] = list(references)
    existing_desc = str(merged.get("description") or "").strip()
    intel_desc = str(description or "").strip()
    existing_low_signal = (
        not existing_desc
        or existing_desc.lower().startswith("vulhub target seed:")
        or existing_desc.lower().startswith("benchmark seed target:")
        or len(existing_desc) < 48
    )
    if intel_desc and existing_low_signal:
        merged["description"] = description
    if family and cve_id and (not merged.get("title") or " - " in str(merged.get("title") or "")):
        merged["title"] = f"{cve_id} - {family}"
    return merged


def get_wooyun_retriever() -> VulnRetriever:
    return get_retriever()


def retrieve_cases(
    query: str,
    top_k: int = 5,
    prefer_cve: bool = False,
    min_severity: Optional[str] = None,
) -> str:
    return _retrieve_cases_cached(query, top_k=top_k, prefer_cve=prefer_cve, min_severity=min_severity)


@lru_cache(maxsize=128)
def _retrieve_cases_cached(
    query: str,
    top_k: int = 5,
    prefer_cve: bool = False,
    min_severity: Optional[str] = None,
) -> str:
    retriever = get_retriever()
    results = retriever.retrieve(query, top_k=top_k, prefer_cve=prefer_cve, min_severity=min_severity)
    return retriever.format_results(results)


def retrieve_cve_intel(query: str, top_k: int = 3, min_severity: str = "medium") -> str:
    return _retrieve_cve_intel_cached(query, top_k=top_k, min_severity=min_severity)


@lru_cache(maxsize=128)
def _retrieve_cve_intel_cached(query: str, top_k: int = 3, min_severity: str = "medium") -> str:
    retriever = get_retriever()
    results = retriever.retrieve_cve(query, top_k=top_k, min_severity=min_severity)
    return retriever.format_results(results, include_probe=True)


def retrieve_wooyun_cases(query: str, top_k: int = 3) -> str:
    return retrieve_cases(query, top_k=top_k)


@lru_cache(maxsize=128)
def _retrieve_cve_ids_cached(query: str, top_k: int = 3, min_severity: str = "medium") -> Tuple[str, ...]:
    retriever = get_retriever()
    results = retriever.retrieve_cve(query, top_k=top_k, min_severity=min_severity)
    return tuple(str(item.get("id") or "").upper() for item in results if str(item.get("id") or "").upper().startswith("CVE-"))


def retrieve_cve_records(query: str, top_k: int = 3, min_severity: str = "medium") -> List[Dict]:
    retriever = get_retriever()
    ids = _retrieve_cve_ids_cached(query, top_k=top_k, min_severity=min_severity)
    return [
        _enrich_cve_entry(dict(retriever.id_map.get(cve_id) or {}))
        for cve_id in ids
        if retriever.id_map.get(cve_id)
    ]


def get_cve_entry(cve_id: str) -> Optional[Dict]:
    normalized = str(cve_id or "").strip().upper()
    if not normalized.startswith("CVE-"):
        return None
    retriever = get_retriever()
    entry = retriever.id_map.get(normalized)
    return _enrich_cve_entry(dict(entry) if isinstance(entry, dict) else None)
