import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, List


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build_runtime_map(runtime_data: Dict) -> Dict[str, str]:
    mapping = {}
    for item in runtime_data.get("targets", []) or []:
        tid = (item.get("id") or "").strip()
        url = (item.get("url") or "").strip()
        if tid and url:
            mapping[tid] = url
    return mapping


def main():
    parser = argparse.ArgumentParser(description="Run arena benchmark targets in batch mode.")
    parser.add_argument("--benchmark", default="benchmarks/known_cve_targets.json")
    parser.add_argument("--runtime", default="benchmarks/arena_runtime_targets.json")
    parser.add_argument("--retry", type=int, default=1)
    parser.add_argument("--python", default="uv run python")
    parser.add_argument("--max-targets", type=int, default=0, help="0 means all")
    args = parser.parse_args()

    benchmark = load_json(Path(args.benchmark))
    runtime_map = build_runtime_map(load_json(Path(args.runtime)))

    targets: List[Dict] = benchmark.get("targets", []) or []
    if args.max_targets > 0:
        targets = targets[: args.max_targets]

    run_results = []
    for t in targets:
        tid = t.get("id")
        if not tid:
            continue
        url = runtime_map.get(tid)
        if not url:
            run_results.append({"id": tid, "status": "skipped", "reason": "missing runtime url"})
            continue

        cmd = (
            f"{args.python} main.py -t {url} --target-id {tid} --benchmark {args.benchmark} -r {args.retry}"
        )
        print(f"[RUN] {tid} -> {url}")
        proc = subprocess.run(cmd, shell=True)
        run_results.append(
            {
                "id": tid,
                "url": url,
                "status": "ok" if proc.returncode == 0 else "failed",
                "return_code": proc.returncode,
            }
        )

    out = {
        "total": len(run_results),
        "ok": len([x for x in run_results if x["status"] == "ok"]),
        "failed": len([x for x in run_results if x["status"] == "failed"]),
        "skipped": len([x for x in run_results if x["status"] == "skipped"]),
        "results": run_results,
    }

    output_path = Path("benchmarks") / "arena_batch_run_result.json"
    output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
