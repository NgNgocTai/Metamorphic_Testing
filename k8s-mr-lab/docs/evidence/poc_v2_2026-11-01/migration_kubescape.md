# Migration impact: kubescape

old runs: runs/kubescape, docs/evidence/informative_2026-11-01/kubescape-run, docs/evidence/mr07_dev_2026-11-01/kubescape, docs/evidence/mr08_mutation_2026-11-01/pinned, docs/evidence/mr09_requirement_derived_2026-11-01/pinned, docs/evidence/p0_reverification_2026-11-01/kubescape; new run: `runs/poc_v2/kubescape`; old mapping from git `4ca941e`

| category | cases |
|---|---|
| UNCHANGED | 60 |
| EXPECTED_CHANGE | 16 |
| NEW_BEHAVIOR | 0 |
| BUG_FIX | 0 |
| UNEXPECTED_REGRESSION | 0 |
| UNRESOLVED | 0 |

## Every case that is not UNCHANGED

| case | MR | old | new | category | reason |
|---|---|---|---|---|---|
| `MR-01__K1-role-namespace__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__K1-role-namespace__83181ed25b` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-basic__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-basic__83181ed25b` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-secrets-reader__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 4 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-secrets-reader__83181ed25b` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 4 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-workload__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-workload__83181ed25b` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__K1-role-namespace__66de14dad8` | MR-02 | VIOLATION | VIOLATION | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__K1-role-namespace__e89cd9e383` | MR-02 | VIOLATION | VIOLATION | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-basic__66de14dad8` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-basic__e89cd9e383` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-secrets-reader__44d79ab8cf` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-secrets-reader__bd7af0cb0d` | MR-02 | VIOLATION | VIOLATION | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-workload__66de14dad8` | MR-02 | VIOLATION | VIOLATION | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-workload__e89cd9e383` | MR-02 | VIOLATION | VIOLATION | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |

**BLOCKED**: False
