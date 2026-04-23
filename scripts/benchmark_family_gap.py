import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shell_agent.cve.templates import load_template_rules


def load_benchmark(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description="Show benchmark family coverage against current template rules.")
    parser.add_argument(
        "--benchmark",
        default=str(Path(__file__).resolve().parent.parent / "benchmarks" / "known_cve_targets.json"),
    )
    args = parser.parse_args()

    benchmark = load_benchmark(Path(args.benchmark))
    benchmark_families: Set[str] = set((t.get("family") or "unknown") for t in benchmark.get("targets", []))

    templates = load_template_rules()
    template_families = set(t.get("family") for t in templates)

    covered = sorted(benchmark_families.intersection(template_families))
    missing = sorted(benchmark_families.difference(template_families))

    out = {
        "benchmark_family_count": len(benchmark_families),
        "template_family_count": len(template_families),
        "covered_family_count": len(covered),
        "missing_family_count": len(missing),
        "covered_families": covered,
        "missing_families": missing,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

