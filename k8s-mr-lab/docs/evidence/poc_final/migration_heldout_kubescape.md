# Migration impact: kubescape

old runs: runs/heldout_poc_v1/kubescape; new run: `runs/heldout/kubescape`; old mapping from git `4ca941e`

| category | cases |
|---|---|
| UNCHANGED | 317 |
| EXPECTED_CHANGE | 39 |
| NEW_BEHAVIOR | 259 |
| BUG_FIX | 0 |
| UNEXPECTED_REGRESSION | 0 |
| UNRESOLVED | 0 |

## Every case that is not UNCHANGED

| case | MR | old | new | category | reason |
|---|---|---|---|---|---|
| `MR-01__rbac-002-1-read-access-to-secrets__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-002-2-read-access-to-secrets__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-002-3-read-access-to-secrets__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-002-5-read-access-to-secrets__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-003-3-role-use-verb-wildcard__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-004-1-role-creates-pods__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-004-5-cluster-role-creates-pods__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-005-1-role-attaches-to-pods__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-007-1-role-binds-default-serviceaccount__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 3 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-008-3-role-port-forward-pods__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-009-1-role-impersonation__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-010-3-role-manages-rbac__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-010-7-cluster-role-manages-rbac__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-012-3-role-info-disclosure__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-013-1-role-destructive__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-014-1-role-event-deletion__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-015-1-role-core-dns-poisoning__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-020-3-role-manages-rbac__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-020-7-cluster-role-manages-rbac__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__39ef56d618` | MR-01 | PASS | PASS | EXPECTED_CHANGE | 0 key(s) dropped and 6 key(s) added by the documented scope or registry change; result unchanged |
| `MR-01__rbac-022-1-role-can-manage-networkpolicy__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-022-5-cluster-role-can-manage-networkpolicy__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-025-3-access-to-webhook-configuration-objects__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-01__rbac-025-6-cluster-access-to-webhook-configuration-objects__39ef56d618` | MR-01 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 4 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-02__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__159ce67025` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__96cf4b31f3` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__42411cb255` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__cca3addcc9` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__5397bbbee7` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-02__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__8a3e3f8d18` | MR-02 | PASS | PASS | EXPECTED_CHANGE | 4 key(s) dropped and 8 key(s) added by the documented scope or registry change; result unchanged |
| `MR-03__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__61070ee82e` | MR-03 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 3 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-03__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__14373c9bab` | MR-03 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 3 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-05__rbac-002-1-read-access-to-secrets__4cf39b21ca` | MR-05 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 1 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-05__rbac-002-2-read-access-to-secrets__1d3db67a6c` | MR-05 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 1 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-05__rbac-002-3-read-access-to-secrets__6c7c525260` | MR-05 | INCONCLUSIVE | SKIP | EXPECTED_CHANGE | INCONCLUSIVE -> SKIP only through 0 added and 1 dropped key(s) (0 added key(s) without a usable verdict); no key present in both runs changed |
| `MR-06__cm-001-sensitive-key-referenced-in-configmap__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__ns-002-1-place-pod-in-kube-system__31d888bc2c` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-003-1-automount-serviceaccounttoken-by-default__7b840027ff` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-003-5-automount-pod-and-sa__ed2f523a20` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-003-9-no-automount-pod-and-sa__cde59434da` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-009-2-hostipc-flag-set__13a0373f2a` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-014-no-apparmor-profile-defined__a348a4cbc9` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-017-2-no-runasnonroot-defaults-to-root-user__ab8c980240` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-017-6-runasnonroot-is-optional-on-container__80356cbc22` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-018-1-no-runasuser-defaults-to-root-user__22d361ede7` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-018-5-use-uid-set-in-container-takes-precedence__cbcf947818` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-019-4-use-gid-set-in-container-takes-precedence__f69afe1a80` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-021-2-using-sysctl-net.core.rmem-c844ee67__cc1a4e375f` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-023-no-seccomp-profile-defined__8656ee8da3` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-031-2-allowed-privilege-escalation-explicitly__c470f99bbd` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-033-2-root-fs-is-explicitly-writeable__b5e0e4a9b3` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-1-using-insecure-capability-audit-write__b602697f53` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-13-using-insecure-capability-perfmon__8c01d6ec0a` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-17-using-insecure-capability-setuid__fc2e594cb4` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-20-using-insecure-capability-sys-module__d07c4434cd` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-4-using-insecure-capability-dac-overrides__ecf718bc8a` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-035-8-using-insecure-capability-mac-override__3153054e75` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-042-2-volume-with-writeable-hostpath__d4e073b89a` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__pod-044-2-mounting-docker-directory__1f0842a7de` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__psa-002-using--privileged--pod-security-standard-is-insecure__433ddd8c29` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-002-1-read-access-to-secrets__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-002-2-read-access-to-secrets__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-002-3-read-access-to-secrets__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-002-5-read-access-to-secrets__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-003-3-role-use-verb-wildcard__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-004-1-role-creates-pods__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-004-5-cluster-role-creates-pods__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-005-1-role-attaches-to-pods__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-007-1-role-binds-default-serviceaccount__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-008-3-role-port-forward-pods__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-009-1-role-impersonation__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-010-3-role-manages-rbac__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-010-7-cluster-role-manages-rbac__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-012-3-role-info-disclosure__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-013-1-role-destructive__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-014-1-role-event-deletion__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-015-1-role-core-dns-poisoning__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-016-serviceaccount-without-binding__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-020-3-role-manages-rbac__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-020-7-cluster-role-manages-rbac__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-022-1-role-can-manage-networkpolicy__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-022-5-cluster-role-can-manage-networkpolicy__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-025-3-access-to-webhook-configuration-objects__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-025-6-cluster-access-to-webhook-configuration-objects__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rbac-027-1-role-binds-to-anonymous-unauthenticated__skip` | MR-06 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rel-001-no-readinessprobe-defined__9f6c451d84` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__rel-004-2-only-nodeaffinity-is-enough__c26e7bebe3` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__res-002-1-default-memory-limits-from-namespace__fa5b3b1248` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__res-004-1-default-cpu-limits-from-namespace__888b0c883b` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__res-006-1-default-ephemeral-storage-limits-from-namespace__4bf7b51aed` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__res-007-2-no-default-cpu-limits-for-namespace__1a7c1ecce4` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__res-008-3-no-default-memory-limits-for-namespace__73af8d9750` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__sc-001-2-no-proper-imagepullpolicy-set__8d74164a6b` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-06__sc-002-3-no-explicit-tag__ec59a68855` | MR-06 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__cm-001-sensitive-key-referenced-in-configmap__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__ns-002-1-place-pod-in-kube-system__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-003-1-automount-serviceaccounttoken-by-default__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-003-5-automount-pod-and-sa__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-003-9-no-automount-pod-and-sa__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-009-2-hostipc-flag-set__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-014-no-apparmor-profile-defined__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-017-2-no-runasnonroot-defaults-to-root-user__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-017-6-runasnonroot-is-optional-on-container__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-018-1-no-runasuser-defaults-to-root-user__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-018-5-use-uid-set-in-container-takes-precedence__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-019-4-use-gid-set-in-container-takes-precedence__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-021-2-using-sysctl-net.core.rmem-c844ee67__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-023-no-seccomp-profile-defined__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-031-2-allowed-privilege-escalation-explicitly__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-033-2-root-fs-is-explicitly-writeable__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-1-using-insecure-capability-audit-write__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-13-using-insecure-capability-perfmon__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-17-using-insecure-capability-setuid__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-20-using-insecure-capability-sys-module__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-4-using-insecure-capability-dac-overrides__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-035-8-using-insecure-capability-mac-override__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-042-2-volume-with-writeable-hostpath__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__pod-044-2-mounting-docker-directory__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__psa-002-using--privileged--pod-security-standard-is-insecure__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-002-1-read-access-to-secrets__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-002-2-read-access-to-secrets__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-002-3-read-access-to-secrets__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-002-5-read-access-to-secrets__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-003-3-role-use-verb-wildcard__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-004-1-role-creates-pods__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-004-5-cluster-role-creates-pods__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-005-1-role-attaches-to-pods__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-007-1-role-binds-default-serviceaccount__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-008-3-role-port-forward-pods__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-009-1-role-impersonation__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-010-3-role-manages-rbac__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-010-7-cluster-role-manages-rbac__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-012-3-role-info-disclosure__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-013-1-role-destructive__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-014-1-role-event-deletion__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-015-1-role-core-dns-poisoning__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-016-serviceaccount-without-binding__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-020-3-role-manages-rbac__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-020-7-cluster-role-manages-rbac__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__88d323c908` | MR-07 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__a5347af94e` | MR-07 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__1d6c6cbfe5` | MR-07 | None | PASS | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-022-1-role-can-manage-networkpolicy__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-022-5-cluster-role-can-manage-networkpolicy__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-025-3-access-to-webhook-configuration-objects__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-025-6-cluster-access-to-webhook-configuration-objects__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rbac-027-1-role-binds-to-anonymous-unauthenticated__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rel-001-no-readinessprobe-defined__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__rel-004-2-only-nodeaffinity-is-enough__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__res-002-1-default-memory-limits-from-namespace__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__res-004-1-default-cpu-limits-from-namespace__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__res-006-1-default-ephemeral-storage-limits-from-namespace__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__res-007-2-no-default-cpu-limits-for-namespace__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__res-008-3-no-default-memory-limits-for-namespace__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__sc-001-2-no-proper-imagepullpolicy-set__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-07__sc-002-3-no-explicit-tag__skip` | MR-07 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__cm-001-sensitive-key-referenced-in-configmap__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__ns-002-1-place-pod-in-kube-system__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-003-1-automount-serviceaccounttoken-by-default__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-003-5-automount-pod-and-sa__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-003-9-no-automount-pod-and-sa__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-009-2-hostipc-flag-set__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-014-no-apparmor-profile-defined__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-017-2-no-runasnonroot-defaults-to-root-user__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-017-6-runasnonroot-is-optional-on-container__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-018-1-no-runasuser-defaults-to-root-user__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-018-5-use-uid-set-in-container-takes-precedence__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-019-4-use-gid-set-in-container-takes-precedence__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-021-2-using-sysctl-net.core.rmem-c844ee67__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-023-no-seccomp-profile-defined__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-031-2-allowed-privilege-escalation-explicitly__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-033-2-root-fs-is-explicitly-writeable__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-1-using-insecure-capability-audit-write__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-13-using-insecure-capability-perfmon__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-17-using-insecure-capability-setuid__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-20-using-insecure-capability-sys-module__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-4-using-insecure-capability-dac-overrides__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-035-8-using-insecure-capability-mac-override__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-042-2-volume-with-writeable-hostpath__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__pod-044-2-mounting-docker-directory__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__psa-002-using--privileged--pod-security-standard-is-insecure__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-002-1-read-access-to-secrets__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-002-2-read-access-to-secrets__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-002-3-read-access-to-secrets__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-002-5-read-access-to-secrets__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-003-3-role-use-verb-wildcard__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-004-1-role-creates-pods__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-004-5-cluster-role-creates-pods__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-005-1-role-attaches-to-pods__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-007-1-role-binds-default-serviceaccount__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-008-3-role-port-forward-pods__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-009-1-role-impersonation__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-010-3-role-manages-rbac__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-010-7-cluster-role-manages-rbac__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-012-3-role-info-disclosure__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-013-1-role-destructive__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-014-1-role-event-deletion__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-015-1-role-core-dns-poisoning__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-016-serviceaccount-without-binding__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-020-3-role-manages-rbac__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-020-7-cluster-role-manages-rbac__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-022-1-role-can-manage-networkpolicy__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-022-5-cluster-role-can-manage-networkpolicy__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-025-3-access-to-webhook-configuration-objects__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-025-6-cluster-access-to-webhook-configuration-objects__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rbac-027-1-role-binds-to-anonymous-unauthenticated__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rel-001-no-readinessprobe-defined__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__rel-004-2-only-nodeaffinity-is-enough__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__res-002-1-default-memory-limits-from-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__res-004-1-default-cpu-limits-from-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__res-006-1-default-ephemeral-storage-limits-from-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__res-007-2-no-default-cpu-limits-for-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__res-008-3-no-default-memory-limits-for-namespace__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__sc-001-2-no-proper-imagepullpolicy-set__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-08__sc-002-3-no-explicit-tag__skip` | MR-08 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__cm-001-sensitive-key-referenced-in-configmap__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__ns-002-1-place-pod-in-kube-system__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-003-1-automount-serviceaccounttoken-by-default__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-003-5-automount-pod-and-sa__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-003-9-no-automount-pod-and-sa__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-009-2-hostipc-flag-set__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-014-no-apparmor-profile-defined__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-017-2-no-runasnonroot-defaults-to-root-user__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-017-6-runasnonroot-is-optional-on-container__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-018-1-no-runasuser-defaults-to-root-user__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-018-5-use-uid-set-in-container-takes-precedence__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-019-4-use-gid-set-in-container-takes-precedence__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-021-2-using-sysctl-net.core.rmem-c844ee67__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-023-no-seccomp-profile-defined__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-031-2-allowed-privilege-escalation-explicitly__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-033-2-root-fs-is-explicitly-writeable__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-1-using-insecure-capability-audit-write__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-13-using-insecure-capability-perfmon__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-17-using-insecure-capability-setuid__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-20-using-insecure-capability-sys-module__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-4-using-insecure-capability-dac-overrides__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-035-8-using-insecure-capability-mac-override__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-042-2-volume-with-writeable-hostpath__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__pod-044-2-mounting-docker-directory__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__psa-002-using--privileged--pod-security-standard-is-insecure__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-1-read-access-to-secrets__5295ba3cc8` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-1-read-access-to-secrets__a68b06619c` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-2-read-access-to-secrets__4fe7e6f2fe` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-2-read-access-to-secrets__fb62cf3fbe` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-3-read-access-to-secrets__98e74b0cf8` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-3-read-access-to-secrets__c16b4c8a3f` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-002-5-read-access-to-secrets__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-003-3-role-use-verb-wildcard__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-004-1-role-creates-pods__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-004-5-cluster-role-creates-pods__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-005-1-role-attaches-to-pods__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-007-1-role-binds-default-serviceaccount__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-008-3-role-port-forward-pods__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-009-1-role-impersonation__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-010-3-role-manages-rbac__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-010-7-cluster-role-manages-rbac__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-012-3-role-info-disclosure__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-013-1-role-destructive__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-014-1-role-event-deletion__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-015-1-role-core-dns-poisoning__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-016-serviceaccount-without-binding__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-020-3-role-manages-rbac__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-020-7-cluster-role-manages-rbac__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-021-1-only-admins-should-be-able-to-create-persis-c893a953__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-021-2-only-admins-should-be-able-to-update-persis-c8f17af4__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-021-3-only-admins-should-be-able-to-patch-persist-c8a38da5__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-022-1-role-can-manage-networkpolicy__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-022-5-cluster-role-can-manage-networkpolicy__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-024-4-access-to-approval-sub-of-certific-c8d6df8a__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-024-7-cluster-access-to-approval-sub-of-c8f934ef__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-025-3-access-to-webhook-configuration-objects__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-025-6-cluster-access-to-webhook-configuration-objects__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rbac-027-1-role-binds-to-anonymous-unauthenticated__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rel-001-no-readinessprobe-defined__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__rel-004-2-only-nodeaffinity-is-enough__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__res-002-1-default-memory-limits-from-namespace__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__res-004-1-default-cpu-limits-from-namespace__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__res-006-1-default-ephemeral-storage-limits-from-namespace__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__res-007-2-no-default-cpu-limits-for-namespace__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__res-008-3-no-default-memory-limits-for-namespace__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__sc-001-2-no-proper-imagepullpolicy-set__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |
| `MR-09__sc-002-3-no-explicit-tag__skip` | MR-09 | None | SKIP | NEW_BEHAVIOR | case did not exist in the archived runs (new MR, seed or parameter) |

**BLOCKED**: False
