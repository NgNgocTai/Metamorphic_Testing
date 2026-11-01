#!/usr/bin/env bash
# Official PoC rerun from a committed tree: baseline (both scanners, all MRs), KD-001 (affected vs fixed binary), MR-09 mutation.
set -u
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
export PYTHONPATH=src
PY=/home/USER/mrlab-venv/bin/python
OUT=runs/poc_v2
rm -rf $OUT; mkdir -p $OUT
MRS="--mr MR-01 --mr MR-02 --mr MR-03 --mr MR-04 --mr MR-05 --mr MR-06 --mr MR-07 --mr MR-08 --mr MR-09"
SEEDS="seeds/synthetic seeds/historical seeds/candidate"
$PY -m k8s_mr_lab versions > $OUT/versions.log.txt 2>&1
$PY -m k8s_mr_lab mr validate > $OUT/validate.log.txt 2>&1; echo "validate rc=$?"
$PY -m k8s_mr_lab run --scanner trivy --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-v2-baseline --out $OUT/trivy > $OUT/trivy.log.txt 2>&1; echo "trivy rc=$?"
$PY -m k8s_mr_lab run --scanner kubescape --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-v2-baseline --out $OUT/kubescape > $OUT/kubescape.log.txt 2>&1; echo "kubescape rc=$?"
for v in 4.0.11 4.0.12; do
  $PY -m k8s_mr_lab --config runs/_cfg_kd_$v.yaml run --scanner kubescape --seeds $SEEDS --mr MR-02 --experiment-type historical-defect --experiment-id kd001-v$v --out $OUT/kd001/v$v > $OUT/kd001-v$v.log.txt 2>&1; echo "kd001 v$v rc=$?"
done
MUT=/home/USER/kd-mutants/mr09-drop-watch
rm -rf $MUT; mkdir -p /home/USER/kd-mutants
$PY scripts/fault_variant_kubescape.py /home/USER/.kubescape $MUT --control C-0015 --variant drop-watch-verb > $OUT/mutant-build.log.txt 2>&1; echo "mutant build rc=$?"
sed "s#~/.kubescape#$MUT#" config/scanners.yaml > runs/_cfg_mut.yaml
$PY -m k8s_mr_lab --config runs/_cfg_mut.yaml run --scanner kubescape --seeds $SEEDS --mr MR-09 --experiment-type mutation --experiment-id mr09-drop-watch-mutant --out $OUT/mr09-mutant > $OUT/mr09-mutant.log.txt 2>&1; echo "mutant rc=$?"
cp $MUT/FAULT_VARIANT.json $OUT/mr09-mutant-FAULT_VARIANT.json
echo ALL_DONE
