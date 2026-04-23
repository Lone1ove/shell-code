import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import requests

_CURATED_SOURCE_PRIORITY = {
    "benchmark_seed": 5,
    "mainstream_seed": 4,
    "vulhub_seed": 3,
    "github_poc": 2,
    "cveproject": 1,
    "nvd": 1,
}

_BENCHMARK_FAMILY_TO_PRODUCT = {
    "struts2_ognl": "struts2",
    "spring_rce": "spring",
    "phpunit_eval_rce": "php",
    "drupal_rce": "drupal",
    "jboss_deserialization": "jboss",
    "tomcat_put_upload": "tomcat",
    "weblogic_t3_deserialization": "weblogic",
    "shiro_rememberme": "shiro",
    "fastjson_deserialization": "fastjson",
    "log4j_jndi": "log4j",
    "exchange_proxylogon": "exchange",
    "apache_traversal": "apache",
    "confluence_ognl": "confluence",
    "jenkins_rce": "jenkins",
    "elasticsearch_unauthorized": "elasticsearch",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _intel_dir() -> Path:
    d = _project_root() / "data" / "cve_intel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _intel_path() -> Path:
    return _intel_dir() / "cve_intel.json"


def _sync_status_path() -> Path:
    return _intel_dir() / "sync_status.json"


def _benchmark_path() -> Path:
    custom = os.getenv("BENCHMARK_CVE_SEED_PATH", "").strip()
    if custom:
        return Path(custom)
    return _project_root() / "benchmarks" / "known_cve_targets.json"


def _mainstream_seed_path() -> Path:
    custom = os.getenv("MAINSTREAM_CVE_SEED_PATH", "").strip()
    if custom:
        return Path(custom)
    return _project_root() / "data" / "cve_intel" / "mainstream_cve_seed.json"


def _vulhub_root() -> Path:
    custom = os.getenv("VULHUB_ROOT", "").strip()
    if custom:
        return Path(custom)
    # default: sibling directory of this project
    return _project_root().parent / "vulhub"


def _is_vulhub_noise_path(path: Path, root: Path) -> bool:
    """
    Exclude hidden/metadata folders (e.g. .git/.github/.claude) from vulhub scans.
    """
    try:
        rel_parts = path.relative_to(root).parts
    except Exception:
        rel_parts = path.parts
    for part in rel_parts:
        p = str(part).strip()
        if not p:
            continue
        if p.startswith(".") or p.startswith("__"):
            return True
    return False


def _normalize_protocol(text: str) -> List[str]:
    lower = text.lower()
    protocols = []
    if "http" in lower or "web" in lower:
        protocols.append("http")
    if "tcp" in lower:
        protocols.append("tcp")
    if "udp" in lower:
        protocols.append("udp")
    if "ldap" in lower:
        protocols.append("ldap")
    if "rmi" in lower:
        protocols.append("rmi")
    return protocols or ["unknown"]


def _tag_product_family(text: str) -> str:
    lower = text.lower()
    mappings = {
        "struts2": ["struts"],
        "tomcat": ["tomcat"],
        "shiro": ["shiro"],
        "fastjson": ["fastjson"],
        "weblogic": ["weblogic"],
        "spring": ["spring"],
        "log4j": ["log4j", "log4shell"],
        "confluence": ["confluence"],
        "exchange": ["exchange", "proxylogon"],
        "apache": ["apache", "httpd"],
        "php": ["php", "phpunit"],
        "drupal": ["drupal"],
        "joomla": ["joomla"],
        "wordpress": ["wordpress"],
        "jenkins": ["jenkins"],
        "redis": ["redis"],
        "elasticsearch": ["elasticsearch"],
        "jboss": ["jboss", "wildfly"],
        "kibana": ["kibana"],
    }
    for family, patterns in mappings.items():
        if any(pattern in lower for pattern in patterns):
            return family
    return "unknown"


def _tag_prerequisites(text: str) -> List[str]:
    lower = text.lower()
    reqs = []
    if "authentication" in lower or "auth" in lower:
        reqs.append("may_require_auth")
    if "deserialization" in lower or "deserialize" in lower:
        reqs.append("deserialization_path")
    if "upload" in lower or "put" in lower:
        reqs.append("file_upload_or_put")
    if "ognl" in lower:
        reqs.append("ognl_expression_path")
    if "jndi" in lower:
        reqs.append("jndi_lookup_path")
    return reqs or ["unknown"]


def _extract_cve_ids(text: str) -> List[str]:
    return list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)))


def _source_priority(source: Optional[str]) -> int:
    values = [str(x).strip().lower() for x in str(source or "").split(",") if str(x).strip()]
    if not values:
        return 0
    return max(_CURATED_SOURCE_PRIORITY.get(item, 0) for item in values)


def _normalize_curated_family(value: Optional[str]) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "unknown"
    return _BENCHMARK_FAMILY_TO_PRODUCT.get(raw, raw)


def _is_seed_style_description(text: Optional[str]) -> bool:
    lower = str(text or "").strip().lower()
    return lower.startswith("vulhub target seed:") or lower.startswith("benchmark seed target:")


def _record_quality(record: Optional[Dict]) -> float:
    row = dict(record or {})
    score = float(_source_priority(row.get("source"))) * 10.0
    description = str(row.get("description") or "").strip()
    if description:
        if _is_seed_style_description(description):
            score -= 3.0
        else:
            score += min(len(description), 600) / 120.0
    severity = str(row.get("severity") or "").strip().lower()
    if severity and severity != "unknown":
        score += 2.0
    if row.get("cvss") is not None:
        score += 2.0
    refs = list(row.get("references") or [])
    score += min(2.5, len(refs) * 0.1)
    if row.get("poc_available"):
        score += 1.0
    family = _normalize_curated_family(row.get("product_family"))
    if family and family != "unknown":
        score += 1.0
    return score


def _normalize_record(
    cve_id: str,
    source: str,
    description: str,
    severity: Optional[str] = None,
    cvss: Optional[float] = None,
    references: Optional[List[str]] = None,
    poc_available: Optional[bool] = None,
) -> Dict:
    description = description or ""
    family = _tag_product_family(description)
    return {
        "cve_id": cve_id.upper(),
        "source": source,
        "description": description[:4000],
        "severity": severity or "unknown",
        "cvss": cvss,
        "product_family": family,
        "protocols": _normalize_protocol(description),
        "prerequisites": _tag_prerequisites(description),
        "poc_available": bool(poc_available) if poc_available is not None else False,
        "references": references or [],
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


def _fetch_nvd(days: int = 30, limit: int = 300) -> List[Dict]:
    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    out: List[Dict] = []
    start_index = 0
    page_size = min(max(1, limit), 2000)

    while len(out) < limit:
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(page_size, limit - len(out)),
            "startIndex": start_index,
        }
        r = requests.get(url, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            cvss = None
            severity = None
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cv = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss = cv.get("baseScore")
                severity = cv.get("baseSeverity")
            refs = [x.get("url") for x in cve.get("references", []) if x.get("url")]
            out.append(_normalize_record(cve_id, "nvd", desc, severity, cvss, refs))
            if len(out) >= limit:
                break

        total_results = int(data.get("totalResults", 0))
        start_index += len(vulns)
        if start_index >= total_results:
            break

    return out[:limit]


def _fetch_cveproject(limit: int = 300) -> List[Dict]:
    # CVEProject list API now requires CVE-API-ORG header.
    # Fallback strategy: enrich a seed CVE set via per-CVE endpoint.
    out: List[Dict] = []
    seen = set()

    seed_ids: List[str] = []
    for rec in _load_benchmark_seed_records():
        cve = (rec.get("cve_id") or "").upper().strip()
        if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            seed_ids.append(cve)
    for rec in _load_mainstream_seed_records():
        cve = (rec.get("cve_id") or "").upper().strip()
        if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            seed_ids.append(cve)

    for cve_id in sorted(set(seed_ids))[: max(0, limit)]:
        if cve_id in seen:
            continue
        seen.add(cve_id)
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            continue
        item = r.json()
        desc = ""
        refs: List[str] = []
        containers = item.get("containers", {})
        cna = containers.get("cna", {})
        for d in cna.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        refs = [x.get("url") for x in cna.get("references", []) if x.get("url")]
        out.append(_normalize_record(cve_id, "cveproject", desc, references=refs))

    return out[:limit]


def _fetch_github_poc(limit: int = 200) -> List[Dict]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = "https://api.github.com/search/repositories"

    out: List[Dict] = []
    page = 1
    per_page = min(limit, 100)

    while len(out) < limit:
        params = {
            "q": "CVE exploit poc in:name,description,readme",
            "sort": "updated",
            "order": "desc",
            "per_page": min(per_page, limit - len(out)),
            "page": page,
        }
        r = requests.get(url, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        items = data.get("items", [])
        if not items:
            break

        for item in items:
            blob = f"{item.get('name', '')} {item.get('description', '')}"
            cve_ids = _extract_cve_ids(blob)
            if not cve_ids:
                continue
            for cve_id in cve_ids:
                out.append(
                    _normalize_record(
                        cve_id=cve_id,
                        source="github_poc",
                        description=blob,
                        references=[item.get("html_url")] if item.get("html_url") else [],
                        poc_available=True,
                    )
                )
                if len(out) >= limit:
                    break
            if len(out) >= limit:
                break

        page += 1
        if len(items) < per_page:
            break

    return out[:limit]


def _load_existing() -> Dict[str, Dict]:
    p = _intel_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return {x["cve_id"]: x for x in raw.get("records", []) if x.get("cve_id")}
    except Exception:
        return {}


def _load_benchmark_seed_records() -> List[Dict]:
    """
    Seed CVE intel from local benchmark definitions.
    This guarantees arena-known CVEs are represented even when upstream APIs are incomplete.
    """
    path = _benchmark_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []

    out: List[Dict] = []
    for target in data.get("targets", []) or []:
        family = _normalize_curated_family(target.get("family") or "unknown")
        desc_base = f"Benchmark seed target: {target.get('id', 'unknown')} ({target.get('name', 'unknown')})"
        for cve in target.get("expected_cves", []) or []:
            cve_id = (cve or "").strip().upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
                continue
            rec = _normalize_record(
                cve_id=cve_id,
                source="benchmark_seed",
                description=f"{desc_base}. family={family}",
                references=[],
                poc_available=True,
            )
            if family and family != "unknown":
                rec["product_family"] = family
            out.append(rec)
    return out


def _load_mainstream_seed_records() -> List[Dict]:
    """
    Seed mainstream high-impact CVEs from local curated file.
    """
    path = _mainstream_seed_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []

    items = data if isinstance(data, list) else data.get("records", [])
    out: List[Dict] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        cve_id = (item.get("cve_id") or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
            continue
        description = item.get("description") or f"Mainstream CVE seed: {cve_id}"
        rec = _normalize_record(
            cve_id=cve_id,
            source="mainstream_seed",
            description=description,
            severity=item.get("severity"),
            cvss=item.get("cvss"),
            references=item.get("references") or [],
            poc_available=True if item.get("poc_available") is None else bool(item.get("poc_available")),
        )
        if item.get("product_family"):
            rec["product_family"] = _normalize_curated_family(item.get("product_family"))
        if item.get("protocols"):
            rec["protocols"] = [str(x).strip().lower() for x in item.get("protocols", []) if str(x).strip()]
        if item.get("prerequisites"):
            rec["prerequisites"] = [str(x).strip().lower() for x in item.get("prerequisites", []) if str(x).strip()]
        out.append(rec)
    return out


def _load_vulhub_seed_records(max_files: int = 3000) -> List[Dict]:
    """
    Scan local vulhub repository and seed all discovered CVE IDs.
    This provides broad baseline coverage for vulhub CVE scenarios.
    """
    enabled = os.getenv("ENABLE_VULHUB_SEED", "true").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return []
    env_max_files = os.getenv("VULHUB_SEED_MAX_FILES", "").strip()
    if env_max_files.isdigit():
        max_files = max(100, int(env_max_files))

    root = _vulhub_root()
    if not root.exists() or not root.is_dir():
        return []

    out: List[Dict] = []
    files_scanned = 0
    cve_seen_in_dir: Dict[str, set] = {}
    allowed_names = {"readme.md", "readme.zh-cn.md", "readme.en.md", "docker-compose.yml"}

    for path in root.rglob("*"):
        if files_scanned >= max_files:
            break
        if _is_vulhub_noise_path(path, root):
            continue
        if not path.is_file():
            continue
        if path.name.lower() not in allowed_names and not path.name.lower().startswith("cve-"):
            continue

        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_dir = path.parent.relative_to(root).as_posix()
        blob = f"{rel_dir}\n{path.name}\n{text[:120000]}"
        cve_ids = _extract_cve_ids(blob)
        if not cve_ids:
            continue

        dir_seen = cve_seen_in_dir.setdefault(rel_dir, set())
        family = _tag_product_family(f"{rel_dir} {text[:8000]}")
        ref_url = f"https://github.com/vulhub/vulhub/tree/master/{rel_dir}"
        for cve_id in cve_ids:
            if cve_id in dir_seen:
                continue
            dir_seen.add(cve_id)
            rec = _normalize_record(
                cve_id=cve_id,
                source="vulhub_seed",
                description=f"Vulhub target seed: {rel_dir}",
                references=[ref_url],
                poc_available=True,
            )
            if family and family != "unknown":
                rec["product_family"] = family
            out.append(rec)

    return out


def _merge_records(existing: Dict[str, Dict], new_records: List[Dict]) -> Dict[str, Dict]:
    for rec in new_records:
        cve_id = rec.get("cve_id")
        if not cve_id:
            continue
        prev = existing.get(cve_id)
        if not prev:
            existing[cve_id] = rec
            continue

        merged = dict(prev)
        prev_quality = _record_quality(prev)
        rec_quality = _record_quality(rec)
        if rec_quality >= prev_quality:
            merged["description"] = rec.get("description") or prev.get("description", "")
        else:
            merged["description"] = prev.get("description", "") or rec.get("description")
        merged["severity"] = rec.get("severity") if rec.get("severity") not in {None, "unknown"} else prev.get("severity")
        merged["cvss"] = rec.get("cvss") if rec.get("cvss") is not None else prev.get("cvss")
        prev_family = _normalize_curated_family(prev.get("product_family"))
        rec_family = _normalize_curated_family(rec.get("product_family"))
        prev_priority = _source_priority(prev.get("source"))
        rec_priority = _source_priority(rec.get("source"))
        if rec_family != "unknown" and (prev_family == "unknown" or rec_priority >= prev_priority):
            merged["product_family"] = rec_family
        else:
            merged["product_family"] = prev_family if prev_family != "unknown" else prev.get("product_family", "unknown")
        merged["protocols"] = sorted(set((prev.get("protocols") or []) + (rec.get("protocols") or [])))
        merged["prerequisites"] = sorted(set((prev.get("prerequisites") or []) + (rec.get("prerequisites") or [])))
        merged["references"] = sorted(set((prev.get("references") or []) + (rec.get("references") or [])))
        merged["poc_available"] = bool(prev.get("poc_available") or rec.get("poc_available"))
        merged["updated_at"] = rec.get("updated_at", merged.get("updated_at"))
        merged["source"] = ",".join(sorted(set((prev.get("source", "") + "," + rec.get("source", "")).strip(",").split(","))))
        existing[cve_id] = merged
    return existing


def save_intel_records(records: Dict[str, Dict]) -> str:
    p = _intel_path()
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "records_count": len(records),
        "records": sorted(records.values(), key=lambda x: x.get("cve_id", "")),
    }
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(p)


def _load_curated_family_overrides() -> Dict[str, str]:
    overrides: Dict[str, str] = {}

    for item in _load_mainstream_seed_records():
        cve_id = str(item.get("cve_id") or "").strip().upper()
        family = _normalize_curated_family(item.get("product_family"))
        if cve_id and family != "unknown":
            overrides[cve_id] = family

    for item in _load_benchmark_seed_records():
        cve_id = str(item.get("cve_id") or "").strip().upper()
        family = _normalize_curated_family(item.get("product_family"))
        if cve_id and family != "unknown":
            overrides[cve_id] = family

    return overrides


def _load_curated_record_overrides() -> Dict[str, Dict]:
    overrides: Dict[str, Dict] = {}
    # Prefer mainstream curated seed for richer semantic fields.
    for item in _load_mainstream_seed_records():
        cve_id = str(item.get("cve_id") or "").strip().upper()
        if not cve_id:
            continue
        overrides[cve_id] = dict(item)
    # Benchmark seed is mainly for family anchoring/backfill.
    for item in _load_benchmark_seed_records():
        cve_id = str(item.get("cve_id") or "").strip().upper()
        if not cve_id or cve_id in overrides:
            continue
        overrides[cve_id] = dict(item)
    return overrides


def _apply_runtime_curated_overrides(records: List[Dict]) -> List[Dict]:
    overrides = _load_curated_family_overrides()
    record_overrides = _load_curated_record_overrides()
    if not overrides and not record_overrides:
        return [dict(item) for item in (records or []) if isinstance(item, dict)]

    normalized_records: List[Dict] = []
    for item in records or []:
        if not isinstance(item, dict):
            continue
        record = dict(item)
        cve_id = str(record.get("cve_id") or "").strip().upper()
        override_family = overrides.get(cve_id)
        if override_family:
            record["product_family"] = override_family
        curated = dict(record_overrides.get(cve_id) or {})
        if curated:
            current_desc = str(record.get("description") or "").strip()
            curated_desc = str(curated.get("description") or "").strip()
            if curated_desc and (
                not current_desc
                or _is_seed_style_description(current_desc)
                or len(current_desc) < 48
            ):
                record["description"] = curated_desc
            current_severity = str(record.get("severity") or "").strip().lower()
            curated_severity = str(curated.get("severity") or "").strip().lower()
            if current_severity in {"", "unknown"} and curated_severity and curated_severity != "unknown":
                record["severity"] = curated_severity
            if record.get("cvss") is None and curated.get("cvss") is not None:
                record["cvss"] = curated.get("cvss")
            if not list(record.get("references") or []) and list(curated.get("references") or []):
                record["references"] = list(curated.get("references") or [])
            current_protocols = [str(x).strip().lower() for x in (record.get("protocols") or []) if str(x).strip()]
            curated_protocols = [str(x).strip().lower() for x in (curated.get("protocols") or []) if str(x).strip()]
            if (not current_protocols or current_protocols == ["unknown"]) and curated_protocols:
                record["protocols"] = curated_protocols
            current_prereq = [str(x).strip().lower() for x in (record.get("prerequisites") or []) if str(x).strip()]
            curated_prereq = [str(x).strip().lower() for x in (curated.get("prerequisites") or []) if str(x).strip()]
            if (not current_prereq or current_prereq == ["unknown"]) and curated_prereq:
                record["prerequisites"] = curated_prereq
        normalized_records.append(record)
    return normalized_records


def _save_sync_status(payload: Dict) -> None:
    _sync_status_path().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def update_cve_intel(days: int = 30, per_source_limit: int = 300) -> Dict:
    """
    Pull from NVD / CVEProject / GitHub PoC, normalize and persist.
    """
    existing = _load_existing()
    fetched_total = 0
    source_stats: Dict[str, int] = {}
    source_errors: Dict[str, str] = {}

    sources: List[Tuple[str, Callable[[], List[Dict]]]] = [
        ("nvd", lambda: _fetch_nvd(days=days, limit=per_source_limit)),
        ("cveproject", lambda: _fetch_cveproject(limit=per_source_limit)),
        ("github_poc", lambda: _fetch_github_poc(limit=min(per_source_limit, 300))),
    ]

    for source_name, fn in sources:
        try:
            records = fn()
            fetched_total += len(records)
            source_stats[source_name] = len(records)
            existing = _merge_records(existing, records)
        except Exception as exc:
            source_stats[source_name] = 0
            source_errors[source_name] = f"{type(exc).__name__}: {str(exc)}"

    benchmark_seed = _load_benchmark_seed_records()
    if benchmark_seed:
        existing = _merge_records(existing, benchmark_seed)
    source_stats["benchmark_seed"] = len(benchmark_seed)

    mainstream_seed = _load_mainstream_seed_records()
    if mainstream_seed:
        existing = _merge_records(existing, mainstream_seed)
    source_stats["mainstream_seed"] = len(mainstream_seed)

    vulhub_seed = _load_vulhub_seed_records()
    if vulhub_seed:
        existing = _merge_records(existing, vulhub_seed)
    source_stats["vulhub_seed"] = len(vulhub_seed)

    path = save_intel_records(existing)
    result = {
        "path": path,
        "total_records": len(existing),
        "fetched_records": fetched_total,
        "source_stats": source_stats,
        "source_errors": source_errors,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }
    _save_sync_status(result)
    return result


def load_cve_intel_records() -> List[Dict]:
    p = _intel_path()
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return _apply_runtime_curated_overrides(raw.get("records", []))
    except Exception:
        return []
