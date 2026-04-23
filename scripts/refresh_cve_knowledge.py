import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shell_agent.cve.intel import update_cve_intel
from shell_agent.rag.cve_indexer import main as rebuild_cve_rag_index


def main():
    parser = argparse.ArgumentParser(
        description="Refresh CVE knowledge pipeline: sync local intel cache, then rebuild CVE RAG index."
    )
    parser.add_argument("--days", type=int, default=30, help="Lookback days for NVD updates.")
    parser.add_argument("--limit", type=int, default=300, help="Max records per remote source.")
    parser.add_argument(
        "--skip-rag-index",
        action="store_true",
        help="Only update local intel cache and skip rebuilding CVE RAG index.",
    )
    args = parser.parse_args()

    result = {
        "intel_update": update_cve_intel(days=args.days, per_source_limit=args.limit),
        "rag_reindexed": False,
    }
    if not args.skip_rag_index:
        rebuild_cve_rag_index()
        result["rag_reindexed"] = True

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
