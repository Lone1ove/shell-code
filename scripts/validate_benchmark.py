import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set


def load_benchmark(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate(data: Dict) -> Dict:
    targets: List[Dict] = data.get("targets", []) or []
    ids = [t.get("id", "") for t in targets]
    dup_ids = [k for k, v in Counter(ids).items() if k and v > 1]

    unknown_platform = [t.get("id") for t in targets if not t.get("platform")]
    empty_cves = [t.get("id") for t in targets if not (t.get("expected_cves") or [])]

    invalid_cves: Dict[str, List[str]] = {}
    all_cves: Set[str] = set()
    for t in targets:
        tid = t.get("id", "unknown")
        bad: List[str] = []
        for c in t.get("expected_cves", []) or []:
            cv = (c or "").strip().upper()
            if not cv.startswith("CVE-"):
                bad.append(c)
            else:
                all_cves.add(cv)
        if bad:
            invalid_cves[tid] = bad

    return {
        "benchmark_name": data.get("benchmark_name", "unknown"),
        "target_count": len(targets),
        "unique_cve_count": len(all_cves),
        "duplicate_target_ids": dup_ids,
        "missing_platform_targets": unknown_platform,
        "empty_expected_cves_targets": empty_cves,
        "invalid_cves_by_target": invalid_cves,
        "is_valid": not dup_ids and not invalid_cves,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate benchmark target/CVE structure.")
    parser.add_argument(
        "--benchmark",
        default=str(Path(__file__).resolve().parent.parent / "benchmarks" / "known_cve_targets.json"),
    )
    args = parser.parse_args()

    data = load_benchmark(Path(args.benchmark))
    print(json.dumps(validate(data), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
