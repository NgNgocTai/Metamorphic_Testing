"""Copy a run's checkable evidence into a self-contained directory with a checksum manifest.

    python scripts/package_run_evidence.py RUN_DIR OUT_DIR [--mr MR-06 ...] [--result VIOLATION ...]

Always copied: results.json/csv, comparisons.csv, environment.lock.json (and triage.json when present).
Per selected case (a case is selected if its mr_id is in --mr OR its result is in --result): the whole case directory, i.e.
source/followup bundles, diff.patch/json, trace.json, assessment.json, normalized-*.json, the RAW scanner outputs
(scanner-source.json / scanner-followup.json), invocation-*.json and provenance.json.

manifest.json lists every copied file with sha256 and size, plus case_index.json (case_id -> relative directory).
The CSVs are copied byte for byte, so their absolute `raw_output_paths` still name the machine that produced them; use
case_index.json for the portable location. Raw scanner JSON may contain local paths (e.g. /home/<user>/): review before sharing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

RUN_FILES = ("results.json", "results.csv", "comparisons.csv", "environment.lock.json", "triage.json")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--mr", action="append", default=[])
    ap.add_argument("--result", action="append", default=[])
    a = ap.parse_args(argv)
    run, out = Path(a.run_dir), Path(a.out_dir)
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    cases = results["cases"] if isinstance(results, dict) and "cases" in results else results
    # SKIP / INVALID_SOURCE rows never produced a pair, so they have no case directory to package
    no_pair = {"SKIP", "INVALID_SOURCE"}
    chosen = sorted({c["case_id"] for c in cases
                     if c.get("mr_result", c.get("result")) not in no_pair
                     and (c.get("mr_id") in a.mr or c.get("mr_result", c.get("result")) in a.result)})
    missing = [r for r in RUN_FILES[:4] if not (run / r).exists()]
    if missing:
        print(f"error: run directory lacks {missing}; refusing to package an incomplete run")
        return 1
    out.mkdir(parents=True, exist_ok=True)
    for name in RUN_FILES:
        if (run / name).exists():
            shutil.copyfile(run / name, out / name)
    index: dict[str, str] = {}
    for cid in chosen:
        src = run / "cases" / cid
        if not src.is_dir():
            print(f"error: case directory missing for {cid}")
            return 1
        for need in ("assessment.json", "trace.json", "diff.patch", "scanner-source.json", "scanner-followup.json"):
            if not (src / need).exists():
                print(f"error: {cid} lacks {need}; refusing to package an incomplete case")
                return 1
        shutil.copytree(src, out / "cases" / cid, dirs_exist_ok=True)
        index[cid] = f"cases/{cid}"
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name not in ("manifest.json", "case_index.json"))
    (out / "case_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    manifest = {"source_run": run.name, "selected_by": {"mr": a.mr, "result": a.result}, "n_cases": len(index),
                "files": {p.relative_to(out).as_posix(): {"sha256": sha(p), "bytes": p.stat().st_size} for p in files}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"packaged {len(index)} case(s), {len(files)} file(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
