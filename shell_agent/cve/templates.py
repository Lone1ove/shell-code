import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _rules_path() -> Path:
    custom = os.getenv("CVE_TEMPLATE_RULES_PATH", "").strip()
    if custom:
        return Path(custom)
    return _project_root() / "data" / "cve_templates" / "families.json"


def _validate_rule(rule: Dict) -> bool:
    required = {
        "template_id",
        "family",
        "vuln_type",
        "products",
        "protocols",
        "preconditions",
        "fingerprint_keywords",
        "default_probe",
        "confirm_markers",
        "false_positive_markers",
        "remediation",
    }
    return all(key in rule for key in required)


def load_template_rules() -> List[Dict]:
    path = _rules_path()
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, list):
            return []
        rules = [r for r in raw if isinstance(r, dict) and _validate_rule(r)]
        # Normalize list fields to lowercase for robust keyword matching.
        for rule in rules:
            rule["products"] = [str(x).lower() for x in rule.get("products", [])]
            rule["protocols"] = [str(x).lower() for x in rule.get("protocols", [])]
            rule["preconditions"] = [str(x).lower() for x in rule.get("preconditions", [])]
            rule["fingerprint_keywords"] = [str(x).lower() for x in rule.get("fingerprint_keywords", [])]
            rule["confirm_markers"] = [str(x).lower() for x in rule.get("confirm_markers", [])]
            rule["false_positive_markers"] = [str(x).lower() for x in rule.get("false_positive_markers", [])]
            rule["remediation"] = [str(x) for x in rule.get("remediation", [])]
        return rules
    except Exception:
        return []


CVE_FAMILY_TEMPLATES: List[Dict] = load_template_rules()


def _extract_product_family(evidence_text: str) -> Optional[str]:
    lower = evidence_text.lower()
    family_aliases = {
        "flask": ["flask", "jinja", "jinja2", "render_template"],
        "struts2": ["struts2", "ognl", "s2-045", "s2-057"],
        "tomcat": ["tomcat", "jsp"],
        "shiro": ["shiro", "rememberme"],
        "fastjson": ["fastjson", "autotype"],
        "spring": ["spring", "spring4shell"],
        "log4j": ["log4j", "log4shell", "${jndi:"],
        "confluence": ["confluence"],
        "exchange": ["exchange", "proxylogon"],
        "apache": ["apache", "httpd"],
        "phpunit": ["phpunit", "eval-stdin.php"],
        "drupal": ["drupal", "drupalgeddon"],
        "joomla": ["joomla"],
        "wordpress": ["wordpress", "wp-content"],
        "jenkins": ["jenkins", "groovy", "script console"],
        "redis": ["redis"],
        "elasticsearch": ["elasticsearch", "_cat"],
        "jboss": ["jboss", "wildfly"],
        "weblogic": ["weblogic", "t3"],
        "kibana": ["kibana", "timelion"],
    }
    for product, keys in family_aliases.items():
        if any(_keyword_matches(lower, key) for key in keys):
            return product
    return None


def _keyword_matches(lower_text: str, keyword: str) -> bool:
    kw = str(keyword or "").strip().lower()
    if not kw:
        return False
    if kw in {"put", "jsp", "sql", "xss", "rce"}:
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", lower_text))
    if re.fullmatch(r"[a-z0-9_-]+", kw):
        return bool(re.search(rf"\b{re.escape(kw)}\b", lower_text))
    return kw in lower_text


def _looks_like_ssti_vector(evidence_text: str) -> bool:
    lower = (evidence_text or "").lower()
    has_expr = bool(re.search(r"\{\{.{1,500}\}\}", lower, re.DOTALL))
    has_deterministic = bool(re.search(r"\{\{\s*\d{1,4}\s*\*\s*\d{1,4}\s*\}\}", lower))
    has_chain = any(
        marker in lower
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
    return has_deterministic or (has_expr and has_chain)


def generate_candidates(
    evidence_text: str,
    cve_id: Optional[str] = None,
    expected_vuln_type: Optional[str] = None,
) -> List[Dict]:
    candidates: List[Dict] = []
    rules = CVE_FAMILY_TEMPLATES or load_template_rules()
    family = _extract_product_family(evidence_text)
    lower = evidence_text.lower()

    for tpl in rules:
        products = tpl.get("products", [])
        keywords = tpl.get("fingerprint_keywords", [])
        matched_keywords = [k for k in keywords if _keyword_matches(lower, k)]

        if family and products and family not in products:
            continue
        if not family and keywords and not matched_keywords:
            # SSTI 常见为 payload/回显证据，不一定显式包含 "ssti" 关键词。
            if (tpl.get("vuln_type") or "").strip().lower() == "ssti" and _looks_like_ssti_vector(lower):
                matched_keywords = ["__ssti_vector__"]
            else:
                continue

        match_score = len(matched_keywords)
        if expected_vuln_type and (tpl.get("vuln_type") or "").lower() == expected_vuln_type.lower():
            match_score += 3

        candidate = {
            "template_id": tpl.get("template_id"),
            "family": tpl.get("family"),
            "vuln_type": tpl.get("vuln_type"),
            "matched_keywords": matched_keywords[:12],
            "match_score": match_score,
            "preconditions": tpl.get("preconditions", []),
            "default_probe": tpl.get("default_probe", ""),
            "confirm_markers": tpl.get("confirm_markers", []),
            "false_positive_markers": tpl.get("false_positive_markers", []),
            "remediation": tpl.get("remediation", []),
            "products": products,
            "protocols": tpl.get("protocols", []),
        }
        if cve_id:
            candidate["cve"] = cve_id.upper()
        candidates.append(candidate)

    candidates.sort(key=lambda x: x.get("match_score", 0), reverse=True)
    return candidates
