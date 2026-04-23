import re
from typing import Dict, List
from urllib.parse import urlparse


def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"https?://[^\s'\"`<>]+", str(text), flags=re.IGNORECASE)


def normalize_endpoint_url(url: str) -> str:
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


def normalize_endpoint_identity(endpoint: str, fallback_target: str = "") -> str:
    raw = normalize_endpoint_url(endpoint or fallback_target)
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


def infer_finding_endpoint_identity(finding: Dict, fallback_target: str = "") -> str:
    candidates: List[str] = []
    for item in (finding.get("request_evidence") or []):
        candidates.extend(extract_urls_from_text(str(item)))
    for item in (finding.get("response_evidence") or []):
        candidates.extend(extract_urls_from_text(str(item)))
    candidates.extend(extract_urls_from_text(str(finding.get("evidence") or "")))

    if candidates:
        return normalize_endpoint_identity(candidates[0], fallback_target)
    return normalize_endpoint_identity("", fallback_target)


def finding_identity_key(finding: Dict, fallback_target: str = "") -> str:
    endpoint = infer_finding_endpoint_identity(finding, fallback_target)
    cve = str(finding.get("cve") or "").strip().upper()
    vuln_type = str(finding.get("vuln_type") or "unknown").strip().lower()
    if cve:
        return f"endpoint:{endpoint}|cve:{cve}|type:{vuln_type}"
    template_id = str(finding.get("template_id") or "").strip().lower()
    if template_id:
        return f"endpoint:{endpoint}|type:{vuln_type}|template:{template_id}"
    vuln_name = str(finding.get("vuln_name") or "").strip().lower()
    return f"endpoint:{endpoint}|type:{vuln_type}|name:{vuln_name}"
