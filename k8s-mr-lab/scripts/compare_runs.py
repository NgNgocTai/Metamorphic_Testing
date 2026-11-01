"""Row-by-row comparison of two run directories (e.g. the poc-v1.0.0 run vs a run after a refactor).

    python scripts/compare_runs.py runs/trivy /path/to/new/trivy

Compares results.csv and comparisons.csv. NOTE: in results.csv the source/follow-up verdict columns are only filled for
violating cases, so the per-key PASS/FAIL verdicts are compared through comparisons.csv, not results.csv.
Fails (exit 1) on a duplicate key in either file, a different row count, a missing row, or any differing value.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

RESULTS_KEY = ("case_id", "target_control", "target_resource")
RESULTS_VALUES = ("mr_result", "source_verdict", "followup_verdict", "pair_status", "skip_reason", "inconclusive_reason",
                  "source_sha256", "followup_sha256")
COMPARISON_KEY = ("case_id", "control", "resource")
COMPARISON_VALUES = ("source_verdict", "followup_verdict", "outcome", "reason")


def load(path: Path, key: tuple, values: tuple) -> dict[tuple, tuple]:
    out: dict[tuple, tuple] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            k = tuple(r[c] for c in key)
            if k in out:
                raise ValueError(f"{path}: duplicate key {k}")
            out[k] = tuple(r[c] for c in values)
    return out


def compare(a: Path, b: Path, name: str, key: tuple, values: tuple) -> int:
    try:
        old, new = load(a / name, key, values), load(b / name, key, values)
    except ValueError as e:
        print(f"ERROR {e}")
        return 1
    bad = 0 if len(old) == len(new) else 1
    if bad:
        print(f"{name}: row count {len(old)} != {len(new)}")
    for k in sorted(old.keys() | new.keys()):
        if old.get(k) != new.get(k):
            bad += 1
            print(f"DIFF {name} {k}\n  {a}: {old.get(k)}\n  {b}: {new.get(k)}")
    print(f"{name}: {len(old)} vs {len(new)} rows, {bad} difference(s)")
    return bad


def main(a: str, b: str) -> int:
    bad = compare(Path(a), Path(b), "results.csv", RESULTS_KEY, RESULTS_VALUES)
    bad += compare(Path(a), Path(b), "comparisons.csv", COMPARISON_KEY, COMPARISON_VALUES)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
