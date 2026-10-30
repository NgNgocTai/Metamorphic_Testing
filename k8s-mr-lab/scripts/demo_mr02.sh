#!/usr/bin/env bash
# Advisor demo: MR-02 with the real Kubescape (run inside Ubuntu/WSL). Secondary demo: ./demo_mr02.sh --scanner trivy
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${PY:-$HOME/mrlab-venv/bin/python}" scripts/demo_mr02.py "$@"
