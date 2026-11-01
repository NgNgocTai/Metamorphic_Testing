"""Row-by-row comparison of two run directories' results.csv (e.g. the poc-v1.0.0 run vs a run after a refactor).

    python scripts/compare_runs.py runs/trivy /path/to/new/trivy

Compares, per (case_id, control, resource): MR result, source/follow-up verdicts, pair status, skip/inconclusive reason and the
sha256 of the exact scanned source and follow-up text. Exits 1 on any difference or on a row present in only one run.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

FIELDS = ("mr_result", "source_verdict", "followup_verdict", "pair_status", "skip_reason", "inconclusive_reason",
          "source_sha256", "followup_sha256")


def rows(run: Path) -> dict[tuple, tuple]:
    with open(run / "results.csv", newline="", encoding="utf-8") as f:
        return {(r["case_id"], r["target_control"], r["target_resource"]): tuple(r[k] for k in FIELDS) for r in csv.DictReader(f)}


def main(a: str, b: str) -> int:
    old, new = rows(Path(a)), rows(Path(b))
    bad = 0
    for k in sorted(old.keys() | new.keys()):
        if old.get(k) != new.get(k):
            bad += 1
            print(f"DIFF {k}\n  {a}: {old.get(k)}\n  {b}: {new.get(k)}")
    print(f"{len(old)} vs {len(new)} rows, {bad} difference(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
