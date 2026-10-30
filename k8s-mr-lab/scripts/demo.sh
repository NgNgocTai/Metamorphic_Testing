#!/usr/bin/env bash
# End-to-end PoC demo with the REAL pinned scanners (Ubuntu/WSL). Takes ~6-8 minutes (Kubescape dominates).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-$HOME/mrlab-venv/bin/python}"

echo "== 1. pins";            $PY -m k8s_mr_lab versions
echo "== 2. tests";           $PY -m pytest -q
echo "== 3. fresh runs";      rm -rf runs/trivy runs/kubescape runs/summary runs/generated
$PY -m k8s_mr_lab generate --seeds seeds/synthetic seeds/historical --out runs/generated | tail -3
$PY -m k8s_mr_lab run --scanner trivy     --seeds seeds/synthetic seeds/historical --out runs/trivy     | tail -2
$PY -m k8s_mr_lab run --scanner kubescape --seeds seeds/synthetic seeds/historical --out runs/kubescape | tail -2
echo "== 4. triage";          $PY -m k8s_mr_lab triage --run runs/trivy --minimize | tail -2
$PY -m k8s_mr_lab triage --run runs/kubescape --minimize | tail -2
echo "== 5. report";          $PY -m k8s_mr_lab report --runs runs/trivy runs/kubescape --out runs/summary > /dev/null
echo "== 6. ablation probes (docs/evidence)"; $PY scripts/triage_probe.py | tail -12
echo "done -> runs/summary/REPORT.md, runs/*/reproducers/, docs/evidence/. Advisor demo: scripts/demo_mr02.sh"
