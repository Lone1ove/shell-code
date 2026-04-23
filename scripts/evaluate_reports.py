import argparse
import json
from typing import Dict, List

from report_loader import load_reports


from pathlib import Path


def _intel_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "cve_intel" / "cve_intel.json"


def evaluate(reports: List[Dict]) -> Dict:
    total_findings = 0
    confirmed = 0
    suspected = 0
    rejected = 0
    elapsed_total = 0.0
    report_count = 0
    family_dist: Dict[str, int] = {}
    cve_verdict_dist: Dict[str, int] = {}
    uncertain_cve_count = 0
    confirmed_unique_cves = set()

    for r in reports:
        report_count += 1
        summary = r.get("summary", {})
        elapsed_total += float(summary.get("elapsed_time", 0) or 0)
        for f in r.get("findings", []):
            total_findings += 1
            status = (f.get("status") or "suspected").lower()
            cve_verdict = (f.get("cve_verdict") or "absent").lower()
            cve_verdict_dist[cve_verdict] = cve_verdict_dist.get(cve_verdict, 0) + 1
            if f.get("cve") and cve_verdict in {"invalid_format", "unverified", "weak_match"}:
                uncertain_cve_count += 1
            if status == "confirmed" and cve_verdict == "confirmed":
                cve = (f.get("cve") or "").strip().upper()
                if cve.startswith("CVE-"):
                    confirmed_unique_cves.add(cve)
            if status == "confirmed":
                confirmed += 1
                fam = f.get("template_id") or f.get("vuln_type", "unknown")
                family_dist[fam] = family_dist.get(fam, 0) + 1
            elif status == "rejected":
                rejected += 1
            else:
                suspected += 1

    fpr = (rejected / total_findings) if total_findings else 0.0
    avg_detection_time = (elapsed_total / report_count) if report_count else 0.0
    coverage_confirmed_ratio = (confirmed / total_findings) if total_findings else 0.0
    intel_total = 0
    if _intel_path().exists():
        try:
            raw = json.loads(_intel_path().read_text(encoding="utf-8-sig"))
            intel_total = int(raw.get("records_count", 0) or len(raw.get("records", [])))
        except Exception:
            intel_total = 0
    global_cve_coverage = (len(confirmed_unique_cves) / intel_total) if intel_total else 0.0

    return {
        "reports_count": report_count,
        "total_findings": total_findings,
        "confirmed_count": confirmed,
        "suspected_count": suspected,
        "rejected_count": rejected,
        "false_positive_rate": round(fpr, 4),
        "avg_detection_time_seconds": round(avg_detection_time, 2),
        "confirmed_coverage_ratio": round(coverage_confirmed_ratio, 4),
        "cve_family_distribution": family_dist,
        "uncertain_cve_count": uncertain_cve_count,
        "cve_verdict_distribution": cve_verdict_dist,
        "confirmed_unique_cve_count": len(confirmed_unique_cves),
        "intel_total_cve_count": intel_total,
        "global_cve_coverage_vs_local_intel": round(global_cve_coverage, 4),
        "meets_global_5_percent_requirement": global_cve_coverage >= 0.05,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate detection quality from generated report JSON files.")
    parser.add_argument("--limit", type=int, default=200, help="Number of latest reports to evaluate.")
    args = parser.parse_args()

    reports = load_reports(limit=args.limit)
    result = evaluate(reports)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
