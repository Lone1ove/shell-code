import argparse
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

from report_loader import load_reports


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_benchmark(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _normalized_cves(values: List[str]) -> Set[str]:
    out: Set[str] = set()
    for c in values or []:
        cve = (c or "").strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


def _extract_confirmed_cves(reports: List[Dict], strict_cve: bool = True) -> Set[str]:
    confirmed_cves: Set[str] = set()
    for r in reports:
        for f in r.get("findings", []):
            if (f.get("status") or "").lower() != "confirmed":
                continue
            if strict_cve and (f.get("cve_verdict") or "absent").lower() != "confirmed":
                continue
            cve = (f.get("cve") or "").upper().strip()
            if cve.startswith("CVE-"):
                confirmed_cves.add(cve)
    return confirmed_cves


def _coverage_tuple(expected: Set[str], observed: Set[str]) -> Tuple[int, int, float, List[str], List[str]]:
    hit = sorted(expected.intersection(observed))
    miss = sorted(expected.difference(observed))
    cov = (len(hit) / len(expected)) if expected else 0.0
    return len(expected), len(hit), cov, hit, miss


def evaluate(benchmark: Dict, reports: List[Dict], strict_cve: bool = True) -> Dict:
    targets = benchmark.get("targets", []) or []
    observed_cves = _extract_confirmed_cves(reports, strict_cve=strict_cve)

    expected_global: Set[str] = set()
    platform_expected: Dict[str, Set[str]] = {}
    target_rows: List[Dict] = []

    for t in targets:
        platform = (t.get("platform") or "unknown").strip()
        target_id = t.get("id") or t.get("name") or "unknown_target"
        target_name = t.get("name") or target_id
        expected = _normalized_cves(t.get("expected_cves", []))

        expected_global.update(expected)
        platform_expected.setdefault(platform, set()).update(expected)

        exp_n, hit_n, cov, hit, miss = _coverage_tuple(expected, observed_cves)
        target_rows.append(
            {
                "id": target_id,
                "name": target_name,
                "platform": platform,
                "expected_known_cve_count": exp_n,
                "confirmed_known_cve_count": hit_n,
                "coverage_confirmed_only": round(cov, 4),
                "hit_cves": hit,
                "miss_cves": miss,
            }
        )

    exp_n, hit_n, cov, hit, miss = _coverage_tuple(expected_global, observed_cves)

    by_platform: Dict[str, Dict] = {}
    for platform, expected in platform_expected.items():
        p_exp_n, p_hit_n, p_cov, p_hit, p_miss = _coverage_tuple(expected, observed_cves)
        by_platform[platform] = {
            "expected_known_cve_count": p_exp_n,
            "confirmed_known_cve_count": p_hit_n,
            "coverage_confirmed_only": round(p_cov, 4),
            "hit_cves": p_hit,
            "miss_cves": p_miss,
        }

    target_rows.sort(key=lambda x: (x["coverage_confirmed_only"], -x["expected_known_cve_count"]))
    top_missing = sorted(miss)[:50]

    return {
        "benchmark_name": benchmark.get("benchmark_name", "unknown"),
        "benchmark_version": benchmark.get("version", "unknown"),
        "strict_cve_attribution": strict_cve,
        "expected_known_cve_count": exp_n,
        "confirmed_known_cve_count": hit_n,
        "coverage_confirmed_only": round(cov, 4),
        "hit_cves": hit,
        "miss_cves": miss,
        "meets_competition_5_percent": cov >= 0.05,
        "coverage_by_platform": by_platform,
        "lowest_coverage_targets": target_rows[:30],
        "top_missing_cves": top_missing,
        "observed_confirmed_cves_from_reports": sorted(observed_cves),
        "report_count": len(reports),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate known-CVE coverage (confirmed only).")
    parser.add_argument(
        "--benchmark",
        default=str(_project_root() / "benchmarks" / "known_cve_targets.json"),
        help="Path to benchmark json",
    )
    parser.add_argument(
        "--non-strict-cve",
        action="store_true",
        help="If set, count confirmed findings even when cve_verdict is not confirmed.",
    )
    args = parser.parse_args()

    benchmark_path = Path(args.benchmark)
    if not benchmark_path.exists():
        raise SystemExit(f"Benchmark not found: {benchmark_path}")

    benchmark = _load_benchmark(benchmark_path)
    result = evaluate(benchmark, load_reports(limit=1000), strict_cve=not args.non_strict_cve)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
