# k8s-mr-lab — MR-first metamorphic testing of Trivy and Kubescape

PoC for the thesis *Detecting Defects in Kubernetes Security Scanners Using Metamorphic Testing*.
A metamorphic relation (MR) both **generates** a follow-up configuration `C2 = T(C1)` and is the **relational oracle**:
the same scanner is run on `C1` and `C2` and the normalized verdicts must satisfy `R(N(S(C1)), N(S(C2)))`.
There is no semantic/reference oracle, no SubjectAccessReview and no cluster in the pipeline (a test guards this).

## Pinned environment (Ubuntu 24.04 in WSL)

| Tool | Version | Mode | Policy pin |
|---|---|---|---|
| Trivy | **0.75.0** | `trivy config <dir>` (local manifest scan) | checks bundle digest from `~/.cache/trivy/policy/metadata.json`, `--skip-check-update` |
| Kubescape | **v4.0.15** | `kubescape scan framework allcontrols <dir>` (local manifest scan) | sha256 of `allcontrols.json` + `controls-inputs.json` + `exceptions.json` in `~/.kubescape`, `--use-artifacts-from` |

The runner refuses to score a pair whose two scans differ in version, mode or policy digest (`ENVIRONMENT_MISMATCH`)
and refuses a binary that is not the pinned version (`SCAN_ERROR`). Both scanners run fully offline.

## Run

```bash
# inside Ubuntu (WSL); the venv holds PyYAML + pytest only
python3 -m venv ~/mrlab-venv && ~/mrlab-venv/bin/pip install -e '.[dev]'
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
PY=~/mrlab-venv/bin/python

$PY -m k8s_mr_lab versions                                   # check the pins
$PY -m pytest -q                                              # 83 tests; 3 integration ones use the real binaries and skip if absent
$PY -m k8s_mr_lab generate --seeds seeds/synthetic seeds/historical --out runs/generated
$PY -m k8s_mr_lab run --scanner trivy     --seeds seeds/synthetic seeds/historical --out runs/trivy
$PY -m k8s_mr_lab run --scanner kubescape --seeds seeds/synthetic seeds/historical --out runs/kubescape   # ~3 min
$PY -m k8s_mr_lab triage --run runs/trivy     --minimize
$PY -m k8s_mr_lab triage --run runs/kubescape --minimize
$PY -m k8s_mr_lab report --runs runs/trivy runs/kubescape --out runs/summary
```

`python scripts/capture_golden.py` re-captures the raw reports in `tests/golden/` from the real binaries.

Advisor demo (about 15 s, real Kubescape): `scripts/demo_mr02.sh`; secondary: `scripts/demo_mr02.sh --scanner trivy --mr MR-05 --out runs/demo_mr05`.
`scripts/triage_probe.py` runs the one-change-at-a-time ablations behind `docs/DEFECT_TRIAGE_RESULTS.md` (`docs/evidence/*.json`).
Independent run on third-party manifests (Kalm-Benchmark) with the catalog frozen first: `python scripts/heldout_prepare.py`
(writes `runs/heldout/freeze.json` + staging), then `bash scripts/heldout_run.sh` (both scanners, triage, report, freeze re-check, ~20 min).
Research questions: RQ1 Applicability, RQ2 Effectiveness, RQ3 Efficiency & Practicality (no random baseline in scope).

## The 5 MRs (`mrs/catalog.yaml`)

| MR | Transformation | Relation | Scope |
|---|---|---|---|
| MR-01 | reverse/sort mapping keys | `equal` | all mapped controls + every FAIL in either report |
| MR-02 | add unbound same-name Role in a fresh namespace | `equal` | bound Role + workload of the bound SA (never the decoy) |
| MR-03 | split a multi-verb rule into one rule per verb | `equal` | effective-permission controls |
| MR-04 | `privileged: false -> true` on one container | `pass_to_fail` | privileged-container control (baseline must be evidenced PASS) |
| MR-05 | core `secrets` rule moved to apiGroup `apps` | `fail_to_pass` | secrets-read controls (baseline must be evidenced FAIL) |

## Result statuses

`PASS` relation held on **every** compared control · `PARTIAL` it held where a verdict existed but part of the scope had none
(never reported as PASS) · `VIOLATION` relation broken (an *alert*, not a confirmed defect) · `SKIP` precondition/scope not
met · `INVALID_SOURCE` / `INVALID_PAIR` bad input or bad transformation · `INCONCLUSIVE` verdict missing or baseline unmet ·
`SCAN_ERROR` binary/timeout/bad JSON/version pin · `ENVIRONMENT_MISMATCH` the two scans were not comparable.
A missing finding is never PASS. Verdicts are `PASS | FAIL | NOT_EVALUATED | UNKNOWN`.

## Evidence rules baked into the code

* Trivy `--include-non-failures` emits PASS entries that are **not attributed to a resource** (verified: 2 Pods → 1 PASS
  entry). A Trivy PASS is therefore an *inference* (kind in the check's `kinds`, check has a PASS entry, no FAIL
  attributed to the resource) and is labelled `pass_inferred` in the evidence. FAILs are attributed by mapping `StartLine`
  onto the exact scanned file.
* Kubescape reports an explicit `passed/failed` per control per resource; RBAC results are aggregated per (subject, Role, RoleBinding) triple
  (ServiceAccount+Role+RoleBinding) and the verdict is given to every member.
* `triage` re-runs the pair, groups alerts into *provisional* families and writes a reproducer; it never sets `CONFIRMED`.

## Layout

`config/` pins + control mapping · `seeds/` synthetic and historical inputs · `mrs/catalog.yaml` ·
`src/k8s_mr_lab/` engine · `tests/{unit,golden,integration}` · `scripts/` demo, probes, golden capture ·
`docs/` · `runs/` generated output (`reproducers/` inside; the numbers are in `runs/summary/REPORT.md`).

Reading order for `docs/`:
0. `HUONG_DAN_BAO_CAO.md` — understand the project and how to present it (script, demo, likely questions).
1. `POC_REPORT_FOR_ADVISOR.md` — the report (problem, method, results, limits, next steps).
2. `DEFECT_TRIAGE_RESULTS.md` — the two defect candidates with evidence (adjudication is yours).
3. `HUONG_DAN_TU_KIEM_TRA.md` — step-by-step to redo the checks yourself.
4. Reference: `SCANNER_VERSIONS.md` (pins and verified CLI/rule facts), `known_issues.yaml`, `evidence/`.
