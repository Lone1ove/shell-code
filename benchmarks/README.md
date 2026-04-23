# Benchmark Guide

`known_cve_targets.json` is the active arena benchmark file used by `scripts/evaluate_cve_coverage.py`.

## Commands

```bash
uv run python scripts/validate_benchmark.py --benchmark benchmarks/known_cve_targets.json
uv run python scripts/benchmark_family_gap.py --benchmark benchmarks/known_cve_targets.json
uv run python scripts/audit_cve_knowledge.py --benchmark benchmarks/known_cve_targets.json --templates data/cve_templates/families.json
uv run python scripts/evaluate_cve_coverage.py --benchmark benchmarks/known_cve_targets.json
```

Batch run by target id (recommended for arena coverage):

```bash
cp benchmarks/arena_runtime_targets.example.json benchmarks/arena_runtime_targets.json
# fill each target id -> runtime URL
uv run python scripts/run_benchmark_batch.py --benchmark benchmarks/known_cve_targets.json --runtime benchmarks/arena_runtime_targets.json --retry 1
uv run python scripts/evaluate_cve_coverage.py --benchmark benchmarks/known_cve_targets.json
```

## High-Coverage Workflow

1. Run target and generate report JSON files into `reports/`.
2. Run `evaluate_cve_coverage.py` to get missing CVEs.
3. Prioritize `top_missing_cves` and `lowest_coverage_targets`.
4. Add or refine family templates in `data/cve_templates/families.json`.
5. Re-run and iterate.

## Notes

- Coverage is counted on `confirmed` findings only.
- By default, CVE attribution must also be `cve_verdict=confirmed` (strict mode).
- Use `--non-strict-cve` only for debugging and internal analysis.
