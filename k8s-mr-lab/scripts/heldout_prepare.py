"""Prepare the independent (held-out style) run on third-party manifests BEFORE looking at any scanner result.

Source: ~/Kalm-Benchmark/manifests (Dynatrace KALM, written by others; never used to design or tune an MR here).
1. Freeze: sha256 of the MR catalog, the control mapping, all MR code and the scanner config -> runs/heldout/freeze.json.
   If any of these files changes afterwards the digest no longer matches and the run must be called development, not held-out.
2. Select (rule fixed here, before running): skip files starting with '_' (benchmark infrastructure, not test cases);
   take every 4th remaining file in sorted order, plus EVERY file to which MR-02, MR-03 or MR-05 applies (they are rare,
   dropping them would hide the RBAC scalability question).
3. Stage each selected file as runs/heldout/staging/<stem>/bundle.yaml (one seed = one file) and record selection.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import BundleError, load_bundle  # noqa: E402
from k8s_mr_lab.registry import load_catalog  # noqa: E402

KALM = Path(os.path.expanduser("~/Kalm-Benchmark/manifests"))
OUT = ROOT / "runs" / "heldout"
FROZEN = ["mrs/catalog.yaml", "config/policy-mapping.yaml", "config/scanners.yaml"] + \
         sorted(str(p.relative_to(ROOT)) for p in (ROOT / "src/k8s_mr_lab").rglob("*.py"))


def digest(paths) -> dict:
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}


def main() -> int:
    if not KALM.is_dir():
        raise SystemExit(f"Benchmark manifests directory not found: {KALM}")
    candidates = sorted(p for p in KALM.glob("*.y*ml") if not p.name.startswith("_"))
    if not candidates:
        raise SystemExit(f"No benchmark manifests found in {KALM}")
    OUT.mkdir(parents=True, exist_ok=True)
    kalm_commit = subprocess.run(["git", "-C", str(KALM.parent), "log", "-1", "--format=%h %ad"], capture_output=True, text=True).stdout.strip()
    files = digest(FROZEN)
    freeze = {"files": files, "overall": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
              "kalm_commit": kalm_commit, "note": "Computed before any held-out scan was run."}
    (OUT / "freeze.json").write_text(json.dumps(freeze, indent=2), encoding="utf-8")

    catalog = load_catalog(ROOT / "mrs/catalog.yaml")
    chosen: dict[str, str] = {}
    unusable = []
    for i, p in enumerate(candidates):
        try:
            b = load_bundle(p, p.stem)
        except BundleError as e:
            unusable.append((p.name, str(e)[:80]))
            continue
        rbac = [m for m in ("MR-02", "MR-03", "MR-05") if catalog[m].applicable(b)[0]]
        if i % 4 == 0:
            chosen[p.name] = "every-4th"
        if rbac:
            chosen[p.name] = f"rbac-applicable({','.join(rbac)})" + (" +every-4th" if i % 4 == 0 else "")
    staging = OUT / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    for name in chosen:
        d = staging / Path(name).stem
        d.mkdir(parents=True)
        shutil.copyfile(KALM / name, d / "bundle.yaml")
    sel = {"kalm_commit": kalm_commit, "candidates": len(candidates), "selected": len(chosen),
           "rule": "skip '_*'; every 4th sorted file; plus every file where MR-02/03/05 applies", "unparsable": unusable,
           "files": chosen}
    (OUT / "selection.json").write_text(json.dumps(sel, indent=2), encoding="utf-8")
    print(f"freeze {freeze['overall'][:16]}  kalm {kalm_commit}\ncandidates {len(candidates)}  selected {len(chosen)}  unparsable {len(unusable)}")
    print("rbac-applicable:", sorted(k for k, v in chosen.items() if v.startswith("rbac")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
