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
cd k8s-mr-lab                                  # the directory containing pyproject.toml (from the repository root)
python3 -m venv ~/mrlab-venv && ~/mrlab-venv/bin/pip install -e '.[dev]'
PY=~/mrlab-venv/bin/python

$PY -m k8s_mr_lab versions                                   # check the pins
$PY -m pytest -q                                              # unit tests; the 3 integration ones use the real binaries and skip if absent (counts: docs/archive/RESEARCH_BASELINE_AUDIT.md)
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

## One framework

One MR declaration (`mrs/catalog.yaml`), one control mapping and scope resolution (`config/policy-mapping.yaml` + the generated
`config/control-registry.yaml`), one pipeline (`Runner` -> `checker` -> `informative.annotate` -> report). There is no second schema,
mapping, checker or execution mode; `mr validate` rejects any inconsistency between the three files. Architecture:
`docs/architecture/UNIFIED_FRAMEWORK.md`; what changed and why: `docs/architecture/LEGACY_TO_UNIFIED_AUDIT.md`,
`docs/poc/MIGRATION_IMPACT_REPORT.md`; the official PoC result: `docs/poc/POC_RESULTS.md`.

## The MRs (`mrs/catalog.yaml`): 5 frozen PoC MRs + 4 candidates (MR-06..MR-09; opt-in with `--mr`, never in default runs)

| MR | Transformation | Relation | Scope |
|---|---|---|---|
| MR-01 | reverse/sort mapping keys | `equal` | all mapped controls + every FAIL in either report |
| MR-02 | add unbound same-name Role in a fresh namespace | `equal` | Kubescape only: workload of the bound SA, and the ServiceAccount + RoleBinding for aggregator controls (never the decoy); Trivy declared `unsupported` |
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

`config/` pins, MR->control mapping, generated control registry · `seeds/` synthetic and historical inputs · `mrs/catalog.yaml` ·
`src/k8s_mr_lab/` engine · `tests/{unit,golden,integration}` · `scripts/` demo, probes, golden capture ·
`docs/` · `runs/` generated output (`reproducers/` inside; the numbers are in `runs/summary/REPORT.md`).

Reading order for `docs/`:
0. `HUONG_DAN_BAO_CAO.md` — understand the project and how to present it (script, demo, likely questions).
1. `poc/POC_REPORT_FOR_ADVISOR.md` — the report (problem, method, results, limits, next steps).
2. `DEFECT_TRIAGE_RESULTS.md` — the two defect candidates with evidence (adjudication is yours).
3. `HUONG_DAN_TU_KIEM_TRA.md` — step-by-step to redo the checks yourself.
4. Reference: `SCANNER_VERSIONS.md` (pins and verified CLI/rule facts), `known_issues.yaml`, `evidence/`.

## Building and understanding MRs

Method: security requirement -> security property (`mrs/security_properties.yaml`, every reference carries `verified`) ->
MR pattern (`mrs/patterns.yaml`) -> MR spec (`mrs/catalog.yaml`, single source of metadata) -> executable MR (`transforms/*.py`,
`@implements`) -> evaluation. OWASP/CWE select the domain; they never prove an MR valid.

```bash
k8s-mr-lab mr list                          # catalog, status, pattern, mapped scanners
k8s-mr-lab mr explain MR-02                 # property, pattern, template, controls, preconditions, limits, code and tests
k8s-mr-lab mr explain MR-02 --case <case dir>   # a saved case from its evidence (read-only; never recomputes a verdict)
k8s-mr-lab mr patterns                      # MR x template-element matrix (the MST-wi Table 4 method)
k8s-mr-lab mr trace                         # property -> pattern -> MR -> control matrix
k8s-mr-lab mr validate                      # STRUCTURAL gate, no scanner needed (not a semantic proof)
k8s-mr-lab mr informative --run <run dir with cases/>   # which comparisons could the control observe? (reporting only)
k8s-mr-lab mr review-packet MR-07 --out docs/review_packets/MR-07.md   # packet for an INDEPENDENT reviewer (decision left blank)
k8s-mr-lab mr requirements   # requirement -> MR matrix with coverage X/N
k8s-mr-lab mr scaffold MR-10 my-mr --pattern KP3
k8s-mr-lab seeds coverage --roots seeds/synthetic seeds/historical seeds/candidate --with-mr   # seed inventory / coverage / select / split
```

| Read | For |
|---|---|
| `docs/archive/RESEARCH_BASELINE_AUDIT.md` | what was re-verified, what exists, what does not |
| `docs/CODE_WALKTHROUGH.md` | seed -> assessment, function by function |
| `docs/MR_DERIVATION_METHODOLOGY.md`, `docs/SECURITY_PROPERTY_DERIVATION_GUIDE.md` | how to derive an MR |
| `docs/WEB_MST_TO_K8S_METHOD_MAPPING.md` | what is taken from MST-wi, what is ours |
| `docs/case_studies/MR02_SEMANTIC_CASE_STUDY.md` | a complete worked MR (proof, counterexamples, real evidence) |
| `docs/architecture/UNIFIED_FRAMEWORK.md`, `docs/architecture/HOW_TO_EXTEND_UNIFIED_FRAMEWORK.md`, `docs/MR_SEMANTIC_REVIEW_CHECKLIST.md` | the one framework; adding and reviewing an MR |
| `docs/poc/POC_RESULTS.md`, `docs/poc/MIGRATION_IMPACT_REPORT.md`, `docs/poc/DEMO_GUIDE.md` | official PoC result (generated from evidence), what the migration changed, demo script |
| `docs/MR_PATTERN_TAXONOMY_V2.md`, `docs/MR_CANDIDATE_EVALUATION.md` | patterns and candidate MRs |
| `docs/EVALUATION_PROTOCOL_V2.md`, `docs/RQ2_EFFECTIVENESS_PROTOCOL.md`, `docs/KNOWN_DEFECT_EVALUATION_PLAN.md`, `docs/KNOWN_DEFECT_CATALOG.md` | evaluation design (RQ1-RQ3), known-defect and mutation protocol |
| `docs/INFORMATIVE_COMPARISON_ANALYSIS.md`, `docs/MUTATION_GAP_ANALYSIS.md`, `docs/SUBJECT_NAMESPACE_MR_CANDIDATE.md` | when does an MR PASS carry information; the mutation gap and MR-08 |
| `docs/SEED_COVERAGE_REPORT.md`, `docs/SOURCE_INPUT_GENERATION_V2.md` | seed coverage and input generation |
| `docs/REQUIREMENTS_TO_MR_MATRIX.md`, `mrs/requirements.yaml`, `docs/MR_DERIVATION_WALKTHROUGH_MR09.md` | PoC stage 1: concrete requirements (K01/K02) -> MR, one MR derived end to end |
| `docs/KD001_REPRODUCTION.md` | PoC stage 2: known defect kubescape#2579 reproduced on the buggy vs fixed binary |
| `docs/INDEPENDENT_MR_REVIEW_PROTOCOL.md`, `docs/review_packets/` | independent review of an MR |
| `docs/EVIDENCE_SHARING_AUDIT.md`, `scripts/sanitize_evidence.py` | what in the repository is personal, and the public copy |
| `docs/archive/NEXT_STAGE_RESEARCH_REPORT.md`, `REPLICATE.md` | this stage's report; reproduce from a clean machine |

Official evidence is `docs/evidence/poc_final/` (earlier experiments: `docs/evidence/archive/`), each directory with `manifest.json` (sha256) and `case_index.json`; read `comparisons.csv`, not only
`results.csv` (whose verdict columns are filled only for VIOLATION rows). Tools: `scripts/compare_runs.py`,
`scripts/snapshot_mr_behavior.py`, `scripts/package_run_evidence.py`, `scripts/fault_variant_kubescape.py`.
