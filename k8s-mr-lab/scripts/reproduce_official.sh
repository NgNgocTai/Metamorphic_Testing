#!/usr/bin/env bash
# Portable reproduction of the official PoC experiments (baseline, KD-001, MR-09 mutation). Run from a clean checkout, inside Linux/WSL:
#   OUT=out/repro KUBESCAPE_4_0_11=/path/kubescape-4.0.11 KUBESCAPE_4_0_12=/path/kubescape-4.0.12 bash scripts/reproduce_official.sh
# Stops at the first failure, checks dependencies and pins first, and refuses to write into a non-empty OUT (it never deletes anything).
# The script actually used for the published results is kept unchanged in docs/evidence/poc_final/run_official_experiments.sh (historical record).
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
PY="${PY:-python3}"
OUT="${OUT:-out/repro}"
KS_ARTIFACTS="${KS_ARTIFACTS:-$HOME/.kubescape}"
need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 2; }; }
need "$PY"; need trivy; need kubescape; need git; need sed
for v in 4_0_11 4_0_12; do
  var="KUBESCAPE_$v"; [ -n "${!var:-}" ] && [ -x "${!var}" ] || { echo "set $var to the official kubescape ${v//_/.} binary (docs/KD001_REPRODUCTION.md)" >&2; exit 2; }
done
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then echo "$OUT exists and is not empty: choose another OUT" >&2; exit 2; fi
mkdir -p "$OUT"
git rev-parse HEAD > "$OUT/source_commit.txt"
$PY -m k8s_mr_lab versions | tee "$OUT/versions.log.txt"       # must print OK for both pins
$PY -m k8s_mr_lab mr validate > "$OUT/validate.log.txt"
$PY -m k8s_mr_lab mr requirements > "$OUT/requirements.log.txt"
$PY scripts/verify_evidence.py > "$OUT/verify_evidence.log.txt"
$PY -m pytest tests -q -p no:cacheprovider > "$OUT/pytest.log.txt"
MRS=(--mr MR-01 --mr MR-02 --mr MR-03 --mr MR-04 --mr MR-05 --mr MR-06 --mr MR-07 --mr MR-08 --mr MR-09)
SEEDS=(seeds/synthetic seeds/historical seeds/candidate)
for sc in trivy kubescape; do
  $PY -m k8s_mr_lab run --scanner $sc --seeds "${SEEDS[@]}" "${MRS[@]}" --experiment-type baseline --experiment-id repro-baseline --out "$OUT/$sc" > "$OUT/$sc.log.txt"
done
for v in 4.0.11 4.0.12; do
  var="KUBESCAPE_${v//./_}"
  sed "s#^  binary: kubescape#  binary: ${!var}#; s#^  version: \"v4.0.15\"#  version: \"v$v\"#; s#~/.kubescape#$KS_ARTIFACTS#" config/scanners.yaml > "$OUT/scanners-v$v.yaml"
  $PY -m k8s_mr_lab --config "$OUT/scanners-v$v.yaml" run --scanner kubescape --seeds "${SEEDS[@]}" --mr MR-02 --experiment-type historical-defect --experiment-id repro-kd001-v$v --out "$OUT/kd001/v$v" > "$OUT/kd001-v$v.log.txt"
done
$PY scripts/fault_variant_kubescape.py "$KS_ARTIFACTS" "$OUT/mut-artifacts" --control C-0015 --variant drop-watch-verb > "$OUT/mutant-build.log.txt"
sed "s#~/.kubescape#$PWD/$OUT/mut-artifacts#" config/scanners.yaml > "$OUT/scanners-mutant.yaml"
$PY -m k8s_mr_lab --config "$OUT/scanners-mutant.yaml" run --scanner kubescape --seeds "${SEEDS[@]}" --mr MR-09 --experiment-type mutation --experiment-id repro-mr09-mutant --out "$OUT/mr09-mutant" > "$OUT/mr09-mutant.log.txt"
echo "reproduction finished: $OUT (compare with docs/evidence/poc_final via scripts/compare_runs.py and poc_tables.py)"
