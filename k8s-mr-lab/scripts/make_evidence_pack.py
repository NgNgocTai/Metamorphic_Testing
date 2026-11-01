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
import subprocess
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
                                          "docs/poc/POC_REPORT_FOR_ADVISOR.md", "docs/DEFECT_TRIAGE_RESULTS.md",
                                          "docs/HUONG_DAN_TU_KIEM_TRA.md", "docs/known_issues.yaml", "docs/SCANNER_VERSIONS.md"]]
    out += sorted((ROOT / "docs/evidence").glob("*.json"))
    for base in ("runs", "runs/heldout"):
        for scanner in ("trivy", "kubescape"):
            d = ROOT / base / scanner
            out += [d / f for f in SCANNER_FILES]
            out += sorted((d / "reproducers").rglob("*")) if (d / "reproducers").exists() else []
    out += sorted((ROOT / "runs/summary").glob("*")) + sorted((ROOT / "runs/heldout/summary").glob("*"))
    out += [ROOT / "runs/heldout" / f for f in ("freeze.json", "selection.json", "run.log")]
    return out


REQUIRED = ["runs/heldout/freeze.json", "runs/heldout/selection.json", "runs/heldout/run.log", "runs/summary/REPORT.md",
            "runs/heldout/summary/REPORT.md", "mrs/catalog.yaml", "config/policy-mapping.yaml", "docs/DEFECT_TRIAGE_RESULTS.md"] + \
           [f"runs/{b}{s}/{f}" for b in ("", "heldout/") for s in ("trivy", "kubescape")
            for f in ("results.json", "comparisons.csv", "environment.lock.json", "triage.json")]


def main() -> int:
    if KALM.is_dir():
        add_selection_hashes()
    candidates = wanted()
    missing = [str(p.relative_to(ROOT)) for p in candidates if not p.is_file() and str(p.relative_to(ROOT)).replace("\\", "/") in REQUIRED]
    if missing:
        raise SystemExit(f"required evidence missing, refusing to build an incomplete pack: {missing}")
    for need in ("runs/trivy/reproducers", "runs/kubescape/reproducers", "runs/heldout/trivy/reproducers"):
        if not any((ROOT / need).rglob("reproduce.sh")):
            raise SystemExit(f"no reproduce.sh under {need}")
    files = [p for p in candidates if p.is_file()]
    manifest = {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    commit, tag, dirty = git_state()
    out = OUT.with_name(f"evidence-pack-{tag}.zip") if tag else OUT
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, str(p.relative_to(ROOT)))
        z.writestr("MANIFEST.sha256.json", json.dumps(manifest, indent=2))
        z.writestr("COMMIT.txt", f"commit: {commit}\ntag: {tag or '(none at HEAD)'}\n"
                                 f"tracked changes under k8s-mr-lab when built: {'YES - not an exact snapshot' if dirty else 'none'}\n")
    print(f"{out.relative_to(ROOT)}: {len(files)} files, {out.stat().st_size / 1e6:.1f} MB | commit {commit[:10]} tag {tag or '-'} "
          f"{'(DIRTY)' if dirty else ''}")
    return 0


def git_state() -> tuple[str, str, bool]:
    """(HEAD commit, tag pointing at HEAD or '', whether tracked files under k8s-mr-lab differ from HEAD)."""
    def git(*a: str) -> str:
        r = subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else ""
    return (git("rev-parse", "HEAD") or "unknown", git("tag", "--points-at", "HEAD").splitlines()[0] if git("tag", "--points-at", "HEAD") else "",
            bool(git("status", "--porcelain", "--untracked-files=no", "--", ".")))


if __name__ == "__main__":
    raise SystemExit(main())
