#!/usr/bin/env bash
# Run the frozen catalog on the staged independent seeds with both real scanners, triage, report, and re-check the freeze.
# Do NOT edit mrs/, config/ or src/ between heldout_prepare.py and the end of this script.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-$HOME/mrlab-venv/bin/python}"
H=runs/heldout
$PY -m k8s_mr_lab run --scanner trivy     --seeds $H/staging --out $H/trivy     --max-cases 2 | tail -3
$PY -m k8s_mr_lab run --scanner kubescape --seeds $H/staging --out $H/kubescape --max-cases 2 | tail -3
$PY -m k8s_mr_lab triage --run $H/trivy     | tail -2
$PY -m k8s_mr_lab triage --run $H/kubescape | tail -2
$PY -m k8s_mr_lab report --runs $H/trivy $H/kubescape --out $H/summary > /dev/null
$PY - <<'PY'
import hashlib, json
from pathlib import Path
f = json.load(open("runs/heldout/freeze.json"))
now = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in f["files"]}
changed = [p for p in now if now[p] != f["files"][p]]
print("FREEZE", "INTACT" if not changed else f"BROKEN: {changed}")
if changed:
    raise SystemExit(1)
PY
rm -rf $H/*/triage-work
echo "heldout done -> $H/summary/REPORT.md"
