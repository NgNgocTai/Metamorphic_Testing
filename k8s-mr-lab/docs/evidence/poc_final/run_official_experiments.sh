#!/usr/bin/env bash
# HISTORICAL RECORD of the commands used for docs/evidence/poc_final (machine-specific paths, no fail-fast). For a portable run use scripts/reproduce_official.sh.
# Official PoC rerun from a committed tree. Output goes to runs/final (git-ignored) so that producing evidence never dirties the source tree.
set -u
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
export PYTHONPATH=src
PY=/home/USER/mrlab-venv/bin/python
OUT=runs/final
rm -rf $OUT; mkdir -p $OUT
MRS="--mr MR-01 --mr MR-02 --mr MR-03 --mr MR-04 --mr MR-05 --mr MR-06 --mr MR-07 --mr MR-08 --mr MR-09"
SEEDS="seeds/synthetic seeds/historical seeds/candidate"
git -C . rev-parse HEAD > $OUT/source_commit.txt
{ sha256sum /usr/local/bin/trivy /usr/local/bin/kubescape /home/USER/kd-bins/kubescape-4.0.11 /home/USER/kd-bins/kubescape-4.0.12; $PY --version; $PY -m pip freeze; } > $OUT/environment.txt 2>&1
$PY -m k8s_mr_lab versions > $OUT/versions.log.txt 2>&1
$PY -m k8s_mr_lab mr validate > $OUT/validate.log.txt 2>&1; echo "validate rc=$?"
$PY -m k8s_mr_lab mr requirements > $OUT/requirements.log.txt 2>&1; echo "requirements rc=$?"
$PY scripts/verify_evidence.py > $OUT/verify_evidence.log.txt 2>&1; echo "verify rc=$?"
$PY -m pytest tests -q -p no:cacheprovider > $OUT/pytest.log.txt 2>&1; echo "pytest rc=$?"; tail -1 $OUT/pytest.log.txt
$PY -m k8s_mr_lab run --scanner trivy --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-final-baseline --out $OUT/trivy > $OUT/trivy.log.txt 2>&1; echo "trivy rc=$?"
$PY -m k8s_mr_lab run --scanner kubescape --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-final-baseline --out $OUT/kubescape > $OUT/kubescape.log.txt 2>&1; echo "kubescape rc=$?"
for v in 4.0.11 4.0.12; do
  $PY -m k8s_mr_lab --config runs/_cfg_kd_$v.yaml run --scanner kubescape --seeds $SEEDS --mr MR-02 --experiment-type historical-defect --experiment-id kd001-v$v --out $OUT/kd001/v$v > $OUT/kd001-v$v.log.txt 2>&1; echo "kd001 v$v rc=$?"
done
MUT=/home/USER/kd-mutants/mr09-drop-watch
rm -rf $MUT
$PY scripts/fault_variant_kubescape.py /home/USER/.kubescape $MUT --control C-0015 --variant drop-watch-verb > $OUT/mutant-build.log.txt 2>&1; echo "mutant build rc=$?"
sed "s#~/.kubescape#$MUT#" config/scanners.yaml > runs/_cfg_mut.yaml
$PY -m k8s_mr_lab --config runs/_cfg_mut.yaml run --scanner kubescape --seeds $SEEDS --mr MR-09 --experiment-type mutation --experiment-id mr09-drop-watch-mutant --out $OUT/mr09-mutant > $OUT/mr09-mutant.log.txt 2>&1; echo "mutant rc=$?"
cp $MUT/FAULT_VARIANT.json $OUT/mr09-mutant-FAULT_VARIANT.json
# external regression on Kalm-Benchmark (catalog frozen first; NOT blind: Kalm exposed the MR-01 scope problem)
$PY scripts/heldout_prepare.py > $OUT/heldout-prepare.log.txt 2>&1; echo "prepare rc=$?"
PY=$PY bash scripts/heldout_run.sh > $OUT/heldout-run.log.txt 2>&1; echo "heldout rc=$?"
echo ALL_DONE
