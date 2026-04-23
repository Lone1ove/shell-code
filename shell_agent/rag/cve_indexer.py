"""CVE 数据索引脚本，将项目中的 CVE 数据整合到 RAG 系统。"""

import json
import re
from pathlib import Path
from typing import Dict, List


DATA_DIR = Path(__file__).parent / "data"
CVE_INTEL_PATH = Path(__file__).parent.parent.parent / "data" / "cve_intel" / "cve_intel.json"
CVE_SEED_PATH = Path(__file__).parent.parent.parent / "data" / "cve_intel" / "mainstream_cve_seed.json"
FAMILIES_PATH = Path(__file__).parent.parent.parent / "data" / "cve_templates" / "families.json"

FAMILY_TO_VULN_TYPE = {
    "struts2": "rce",
    "tomcat": "rce",
    "shiro": "rce",
    "fastjson": "rce",
    "log4j": "rce",
    "spring": "rce",
    "confluence": "rce",
    "exchange": "rce",
    "apache": "lfi",
    "php": "rce",
    "drupal": "rce",
    "weblogic": "rce",
    "jboss": "rce",
    "jenkins": "rce",
    "elasticsearch": "auth",
    "kibana": "xss",
    "citrix": "rce",
    "f5": "rce",
    "fortinet": "lfi",
    "pulse": "lfi",
    "vmware": "rce",
    "gitlab": "rce",
    "manageengine": "rce",
    "ivanti": "auth",
    "activemq": "rce",
    "druid": "rce",
    "redis": "auth",
    "wordpress": "rce",
    "joomla": "sqli",
}


def load_families() -> Dict[str, Dict]:
    if not FAMILIES_PATH.exists():
        return {}
    with open(FAMILIES_PATH, "r", encoding="utf-8") as f:
        families = json.load(f)
    return {fam["family"]: fam for fam in families if isinstance(fam, dict) and fam.get("family")}


def load_cve_intel() -> List[Dict]:
    records: List[Dict] = []

    if CVE_INTEL_PATH.exists():
        with open(CVE_INTEL_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            records.extend(data.get("records", []))

    if CVE_SEED_PATH.exists():
        with open(CVE_SEED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            seed_records = data if isinstance(data, list) else data.get("records", [])
            for record in seed_records:
                if isinstance(record, dict):
                    copied = dict(record)
                    copied["is_mainstream"] = True
                    records.append(copied)

    return records


def cve_to_rag_entry(cve: Dict, families: Dict) -> Dict:
    product_family = str(cve.get("product_family") or "unknown").strip().lower()
    vuln_type = FAMILY_TO_VULN_TYPE.get(product_family, "other")

    desc_lower = str(cve.get("description") or "").lower()
    if "sql injection" in desc_lower or "sqli" in desc_lower:
        vuln_type = "sqli"
    elif "xss" in desc_lower or "cross-site scripting" in desc_lower:
        vuln_type = "xss"
    elif "ssrf" in desc_lower or "server-side request" in desc_lower:
        vuln_type = "ssrf"
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        vuln_type = "lfi"
    elif "xxe" in desc_lower or "xml external" in desc_lower:
        vuln_type = "xxe"
    elif "deserialization" in desc_lower or "rce" in desc_lower or "remote code" in desc_lower:
        vuln_type = "rce"
    elif "auth" in desc_lower and ("bypass" in desc_lower or "unauthorized" in desc_lower):
        vuln_type = "auth"
    elif "file upload" in desc_lower:
        vuln_type = "upload"

    entry = {
        "type": vuln_type,
        "id": str(cve.get("cve_id") or "").upper(),
        "title": f"{str(cve.get('cve_id') or '').upper()} - {product_family}",
        "description": str(cve.get("description") or ""),
        "product_family": product_family,
        "severity": str(cve.get("severity") or "unknown").lower(),
        "cvss": cve.get("cvss"),
        "protocols": list(cve.get("protocols") or []),
        "references": list(cve.get("references") or []),
        "is_mainstream": bool(cve.get("is_mainstream", False)),
    }

    family_key = None
    for fam_name, fam_data in families.items():
        if product_family and product_family in [str(x).lower() for x in fam_data.get("products", [])]:
            family_key = fam_name
            break

    if family_key and family_key in families:
        fam = families[family_key]
        entry["default_probe"] = fam.get("default_probe", "")
        entry["confirm_markers"] = list(fam.get("confirm_markers") or [])
        entry["remediation"] = list(fam.get("remediation") or [])
        entry["fingerprint_keywords"] = list(fam.get("fingerprint_keywords") or [])

    raw_parts = [
        f"### [{entry['id']}] {entry['title']}",
        f"**漏洞类型**: {vuln_type}",
        f"**产品**: {product_family}",
        f"**严重程度**: {entry['severity']}",
        f"**描述**: {entry['description']}",
    ]
    if entry.get("default_probe"):
        raw_parts.append(f"**检测方法**: {entry['default_probe']}")
    if entry.get("remediation"):
        raw_parts.append(f"**修复建议**: {'; '.join(entry['remediation'])}")
    entry["raw"] = "\n".join(raw_parts)

    return entry


def merge_with_existing(cve_entries: List[Dict]) -> List[Dict]:
    id_map_path = DATA_DIR / "id_map.json"
    existing_entries: List[Dict] = []
    if id_map_path.exists():
        with open(id_map_path, "r", encoding="utf-8") as f:
            id_map = json.load(f)
            existing_entries = list(id_map.values())

    existing_ids = {str(entry.get("id") or "") for entry in existing_entries}
    for cve_entry in cve_entries:
        if cve_entry["id"] and cve_entry["id"] not in existing_ids:
            existing_entries.append(cve_entry)
    return existing_entries


def build_index(entries: List[Dict]):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    by_type: Dict[str, List[Dict]] = {}
    for entry in entries:
        vuln_type = str(entry.get("type") or "other")
        by_type.setdefault(vuln_type, []).append(entry)

    for vuln_type, type_entries in by_type.items():
        path = DATA_DIR / f"{vuln_type}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(type_entries, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(type_entries)} entries to {path.name}")

    keyword_index: Dict[str, List[str]] = {}
    for entry in entries:
        eid = str(entry.get("id") or "")
        if not eid:
            continue
        text = " ".join(
            [
                str(entry.get("title") or ""),
                str(entry.get("description") or ""),
                str(entry.get("product_family") or ""),
                str(entry.get("raw") or ""),
                " ".join(str(x) for x in (entry.get("fingerprint_keywords") or [])),
            ]
        )
        words = set(re.findall(r"[a-zA-Z0-9\-]{3,}|[\u4e00-\u9fa5]{2,}", text.lower()))
        for word in words:
            keyword_index.setdefault(word, []).append(eid)

    with open(DATA_DIR / "keyword_index.json", "w", encoding="utf-8") as f:
        json.dump(keyword_index, f, ensure_ascii=False)

    id_map = {str(entry["id"]): entry for entry in entries if entry.get("id")}
    with open(DATA_DIR / "id_map.json", "w", encoding="utf-8") as f:
        json.dump(id_map, f, ensure_ascii=False)

    cve_count = sum(1 for entry in entries if str(entry.get("id") or "").startswith("CVE-"))
    wooyun_count = sum(1 for entry in entries if str(entry.get("id") or "").startswith("wooyun-"))
    print("\nIndex built:")
    print(f"  - Total entries: {len(id_map)}")
    print(f"  - CVE entries: {cve_count}")
    print(f"  - WooYun entries: {wooyun_count}")
    print(f"  - Keywords: {len(keyword_index)}")


def main():
    print("Loading CVE data...")
    families = load_families()
    print(f"  Loaded {len(families)} vulnerability family templates")

    cve_records = load_cve_intel()
    print(f"  Loaded {len(cve_records)} CVE records")

    print("\nConverting CVE records to RAG format...")
    cve_entries = [cve_to_rag_entry(cve, families) for cve in cve_records if str(cve.get('cve_id') or '').upper().startswith('CVE-')]

    seen_ids = set()
    unique_entries = []
    for entry in cve_entries:
        if entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        unique_entries.append(entry)
    print(f"  Unique CVE entries: {len(unique_entries)}")

    print("\nMerging with existing WooYun data...")
    all_entries = merge_with_existing(unique_entries)

    print("\nBuilding index...")
    build_index(all_entries)

    print("\nDone!")


if __name__ == "__main__":
    main()
