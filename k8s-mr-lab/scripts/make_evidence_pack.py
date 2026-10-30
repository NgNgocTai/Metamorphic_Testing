"""Build runs/evidence-pack.zip: the small set of files needed to re-check the reported numbers without the ~70 MB of
regenerable per-case artifacts. Also records the sha256 of every selected third-party manifest in selection.json.

Contains: reports, per-scanner results/comparisons/environment locks/triage, reproducer packages (self-contained: source,
follow-up, diff, raw scanner JSON, reproduce.sh), ablation evidence, the freeze record, configs and the MR catalog.
Does NOT contain credentials; raw reports do contain local paths such as /home/<user>/... (review before sharing).
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KALM = Path(os.path.expanduser("~/Kalm-Benchmark/manifests"))
OUT = ROOT / "runs" / "evidence-pack.zip"
SCANNER_FILES = ["results.json", "results.csv", "comparisons.csv", "environment.lock.json", "triage.json"]


def add_selection_hashes() -> None:
    p = ROOT / "runs/heldout/selection.json"
    sel = json.loads(p.read_text(encoding="utf-8"))
    sel["sha256"] = {n: hashlib.sha256((KALM / n).read_bytes()).hexdigest() for n in sorted(sel["files"]) if (KALM / n).exists()}
    p.write_text(json.dumps(sel, indent=2), encoding="utf-8")


def wanted() -> list[Path]:
    out: list[Path] = [ROOT / f for f in ["README.md", "mrs/catalog.yaml", "config/scanners.yaml", "config/policy-mapping.yaml",
                                          "docs/POC_REPORT_FOR_ADVISOR.md", "docs/DEFECT_TRIAGE_RESULTS.md",
                                          "docs/HUONG_DAN_TU_KIEM_TRA.md", "docs/known_issues.yaml", "docs/SCANNER_VERSIONS.md",
                                          "runs/last_demo.log"]]
    out += sorted((ROOT / "docs/evidence").glob("*.json"))
    for base in ("runs", "runs/heldout"):
        for scanner in ("trivy", "kubescape"):
            d = ROOT / base / scanner
            out += [d / f for f in SCANNER_FILES]
            out += sorted((d / "reproducers").rglob("*")) if (d / "reproducers").exists() else []
    out += sorted((ROOT / "runs/summary").glob("*")) + sorted((ROOT / "runs/heldout/summary").glob("*"))
    out += [ROOT / "runs/heldout" / f for f in ("freeze.json", "selection.json", "run.log")]
    return [p for p in out if p.is_file()]


def main() -> int:
    if KALM.is_dir():
        add_selection_hashes()
    files = wanted()
    manifest = {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, str(p.relative_to(ROOT)))
        z.writestr("MANIFEST.sha256.json", json.dumps(manifest, indent=2))
    print(f"{OUT.relative_to(ROOT)}: {len(files)} files, {OUT.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
