import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Set


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


sys.path.insert(0, str(_project_root()))

from shell_agent.cve.intel import load_cve_intel_records


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _expected_cves(benchmark: Dict) -> Set[str]:
    out: Set[str] = set()
    for target in benchmark.get("targets", []) or []:
        for item in target.get("expected_cves", []) or []:
            cve = str(item or "").strip().upper()
            if cve.startswith("CVE-"):
                out.add(cve)
    return out


def _template_families(path: Path) -> Set[str]:
    data = _load_json(path)
    return {str(item.get("family") or "").strip() for item in data if isinstance(item, dict)}


def audit(benchmark_path: Path, template_path: Path) -> Dict:
    benchmark = _load_json(benchmark_path)
    intel_records = load_cve_intel_records()
    intel_map = {
        str(item.get("cve_id") or "").strip().upper(): item
        for item in intel_records
        if isinstance(item, dict) and item.get("cve_id")
    }

    expected = sorted(_expected_cves(benchmark))
    template_families = _template_families(template_path)

    missing_intel: List[str] = []
    family_mismatches: List[Dict] = []
    sparse_metadata: List[Dict] = []
    missing_template_family: Set[str] = set()

    for target in benchmark.get("targets", []) or []:
        benchmark_family = str(target.get("family") or "").strip()
        if benchmark_family and benchmark_family not in template_families:
            missing_template_family.add(benchmark_family)

        for cve in target.get("expected_cves", []) or []:
            cve_id = str(cve or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            record = intel_map.get(cve_id)
            if not record:
                missing_intel.append(cve_id)
                continue

            intel_family = str(record.get("product_family") or "").strip().lower()
            benchmark_family_lower = benchmark_family.lower()
            if benchmark_family_lower and intel_family and benchmark_family_lower not in intel_family and intel_family not in benchmark_family_lower:
                family_mismatches.append(
                    {
                        "target": target.get("id"),
                        "cve": cve_id,
                        "benchmark_family": benchmark_family,
                        "intel_family": intel_family,
                    }
                )

            has_refs = bool(record.get("references"))
            has_desc = bool(str(record.get("description") or "").strip())
            if not (has_desc and has_refs):
                sparse_metadata.append(
                    {
                        "target": target.get("id"),
                        "cve": cve_id,
                        "has_description": has_desc,
                        "has_references": has_refs,
                        "source": record.get("source"),
                    }
                )

    return {
        "benchmark_name": benchmark.get("benchmark_name", "unknown"),
        "expected_known_cve_count": len(expected),
        "intel_record_count": len(intel_map),
        "missing_intel_count": len(missing_intel),
        "missing_intel": sorted(set(missing_intel)),
        "family_mismatch_count": len(family_mismatches),
        "family_mismatch_examples": family_mismatches[:20],
        "sparse_metadata_count": len(sparse_metadata),
        "sparse_metadata_examples": sparse_metadata[:20],
        "missing_template_family_count": len(missing_template_family),
        "missing_template_families": sorted(missing_template_family),
        "is_healthy": not missing_intel and not missing_template_family,
    }


def main():
    parser = argparse.ArgumentParser(description="Audit CVE benchmark/intel/template integrity.")
    parser.add_argument(
        "--benchmark",
        default=str(_project_root() / "benchmarks" / "known_cve_targets.json"),
    )
    parser.add_argument(
        "--templates",
        default=str(_project_root() / "data" / "cve_templates" / "families.json"),
    )
    args = parser.parse_args()

    result = audit(Path(args.benchmark), Path(args.templates))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
