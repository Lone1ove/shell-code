import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def _is_noise_path(path: Path, root: Path) -> bool:
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


def _extract_cves(text: str) -> List[str]:
    cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
    return sorted(set(x.upper() for x in cves))


def _infer_family(blob: str) -> str:
    lower = blob.lower()
    rules = [
        ("struts2_ognl", ["struts", "s2-"]),
        ("tomcat_put_upload", ["tomcat", "put"]),
        ("shiro_rememberme", ["shiro", "rememberme"]),
        ("fastjson_deserialization", ["fastjson", "autotype"]),
        ("spring_rce", ["spring", "spring4shell"]),
        ("log4j_jndi", ["log4j", "log4shell", "${jndi:"]),
        ("confluence_ognl", ["confluence", "ognl"]),
        ("exchange_proxylogon", ["exchange", "proxylogon", "proxyshell"]),
        ("apache_traversal", ["httpd", "apache", "traversal"]),
        ("phpunit_eval_rce", ["phpunit", "eval-stdin.php"]),
        ("drupal_rce", ["drupal", "drupalgeddon"]),
        ("weblogic_t3_deserialization", ["weblogic", "t3"]),
        ("jboss_deserialization", ["jboss", "wildfly", "deserialization"]),
        ("elasticsearch_unauthorized", ["elasticsearch"]),
        ("jenkins_rce", ["jenkins"]),
        ("kibana_rce_or_xss", ["kibana"]),
    ]
    for family, keywords in rules:
        if all(k in lower for k in keywords[:1]) and any(k in lower for k in keywords):
            return family
    return "unknown"


def _build_targets(vulhub_root: Path) -> List[Dict]:
    targets_map: Dict[str, Dict] = {}
    readmes = [p for p in vulhub_root.rglob("README*.md") if not _is_noise_path(p, vulhub_root)]
    for readme in readmes:
        try:
            text = readme.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel_dir = readme.parent.relative_to(vulhub_root).as_posix()
        cves = _extract_cves(f"{rel_dir}\n{text}")
        if not cves:
            continue
        family = _infer_family(f"{rel_dir}\n{text[:12000]}")
        target_id = "vulhub." + rel_dir.replace("/", ".").replace("-", "_")
        existed = targets_map.get(target_id)
        if not existed:
            targets_map[target_id] = {
                "id": target_id,
                "platform": "Vulhub",
                "name": rel_dir,
                "expected_cves": cves,
                "family": family,
            }
            continue
        merged_cves = sorted(set(existed.get("expected_cves", [])) | set(cves))
        existed["expected_cves"] = merged_cves
        if existed.get("family") == "unknown" and family != "unknown":
            existed["family"] = family
    targets = list(targets_map.values())
    targets.sort(key=lambda x: x["id"])
    return targets


def main():
    parser = argparse.ArgumentParser(description="Build benchmark target list from local vulhub repository.")
    parser.add_argument("--vulhub-root", default="../vulhub", help="Path to local vulhub root directory.")
    parser.add_argument(
        "--output",
        default="benchmarks/vulhub_known_cve_targets.generated.json",
        help="Output benchmark json path.",
    )
    args = parser.parse_args()

    vulhub_root = Path(args.vulhub_root).resolve()
    if not vulhub_root.exists():
        raise SystemExit(f"vulhub root not found: {vulhub_root}")

    targets = _build_targets(vulhub_root)
    payload = {
        "benchmark_name": "Vulhub Local Generated Known-CVE Targets",
        "version": datetime.now().strftime("%Y-%m-%d"),
        "description": "Auto-generated from local vulhub repository README files.",
        "targets": targets,
    }
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output), "target_count": len(targets)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
