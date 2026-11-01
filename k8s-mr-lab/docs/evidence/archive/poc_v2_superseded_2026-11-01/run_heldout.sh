#!/usr/bin/env bash
set -u
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
export PYTHONPATH=src
PY=/home/USER/mrlab-venv/bin/python
$PY scripts/heldout_prepare.py > runs/_held_prepare.log.txt 2>&1; echo "prepare rc=$?"
PY=$PY bash scripts/heldout_run.sh > runs/_held_run.log.txt 2>&1; echo "heldout rc=$?"
echo HELD_DONE
