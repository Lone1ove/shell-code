import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shell_agent.cve.intel import update_cve_intel


def main():
    parser = argparse.ArgumentParser(description="Update CVE intelligence from NVD/CVEProject/GitHub PoC sources.")
    parser.add_argument("--days", type=int, default=30, help="Lookback days for NVD updates.")
    parser.add_argument("--limit", type=int, default=300, help="Max records per source.")
    args = parser.parse_args()

    result = update_cve_intel(days=args.days, per_source_limit=args.limit)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

