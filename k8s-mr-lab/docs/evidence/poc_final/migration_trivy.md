# Migration impact: trivy

old runs: runs/trivy, docs/evidence/archive/informative_2026-11-01/trivy-run, docs/evidence/archive/mr07_dev_2026-11-01/trivy, docs/evidence/archive/mr09_requirement_derived_2026-11-01/trivy, docs/evidence/archive/p0_reverification_2026-11-01/trivy, docs/evidence/archive/p0_reverification_2026-11-01/trivy-mr02; new run: `runs/final/trivy`; old mapping from git `4ca941e`

| category | cases |
|---|---|
| UNCHANGED | 57 |
| EXPECTED_CHANGE | 20 |
| NEW_BEHAVIOR | 7 |
| BUG_FIX | 0 |
| UNEXPECTED_REGRESSION | 0 |
| UNRESOLVED | 0 |

## Every case that is not UNCHANGED

| case | MR | old | new | category | reason |
|---|---|---|---|---|---|
| `MR-02__K1-role-namespace__66de14dad8` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__K1-role-namespace__e89cd9e383` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__K1-role-namespace__skip` | MR-02 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-02__rbac-basic__66de14dad8` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-basic__e89cd9e383` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-basic__skip` | MR-02 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-02__rbac-secrets-reader__44d79ab8cf` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-secrets-reader__bd7af0cb0d` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-secrets-reader__skip` | MR-02 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-02__rbac-workload__66de14dad8` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-workload__e89cd9e383` | MR-02 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-02__rbac-workload__skip` | MR-02 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-07__K1-role-namespace__8209b1cbb6` | MR-07 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-07__K1-role-namespace__skip` | MR-07 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-07__rbac-basic__8209b1cbb6` | MR-07 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-07__rbac-basic__skip` | MR-07 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-07__rbac-secrets-reader__88249c50fa` | MR-07 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-07__rbac-secrets-reader__skip` | MR-07 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-07__rbac-workload__8209b1cbb6` | MR-07 | PASS | None | EXPECTED_CHANGE | case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported) |
| `MR-07__rbac-workload__skip` | MR-07 | None | SKIP | EXPECTED_CHANGE | one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping |
| `MR-08__K1-role-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-basic__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-hostnet__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-basic__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-no-binding__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-secrets-reader__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-workload__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |

**BLOCKED**: False
