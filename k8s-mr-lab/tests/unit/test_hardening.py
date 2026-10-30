"""Counterexamples found by the independent review of 2026-10-30. Each test failed on the previous code."""
import json
from pathlib import Path

from k8s_mr_lab.checker import check
from k8s_mr_lab.model import NOT_EVALUATED, PASS, NormalizedReport
from k8s_mr_lab.scanners import make_scanner

RB = "rbac.authorization.k8s.io/v1"
K = ("", "Pod", "n", "p")


class _MR:
    relation, all_failures = "equal", False


def _role(name, ns, rules):
    return {"apiVersion": RB, "kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


def _binding(name, ns, role, sa, kind="Role", bkind="RoleBinding"):
    meta = {"name": name, **({"namespace": ns} if bkind == "RoleBinding" else {})}
    return {"apiVersion": RB, "kind": bkind, "metadata": meta, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": role},
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": "lab-c"}]}


SECRETS_GET = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]


# ---------------- P1-A checker never reports a full PASS over missing verdicts
def test_partial_scope_is_not_a_full_pass():
    r1, r2 = NormalizedReport("x"), NormalizedReport("x")
    r1.add("A", K, PASS); r2.add("A", K, PASS)
    r1.add("B", K, NOT_EVALUATED); r2.add("B", K, NOT_EVALUATED)
    a = check(_MR(), [("A", K), ("B", K)], r1, r2)
    assert a.result == "PARTIAL" and a.counts() == {"ok": 1, "violation": 0, "inconclusive": 1}


def test_violation_still_wins_over_partial():
    r1, r2 = NormalizedReport("x"), NormalizedReport("x")
    r1.add("A", K, PASS); r2.add("A", K, "FAIL"); r1.add("B", K, NOT_EVALUATED)
    assert check(_MR(), [("A", K), ("B", K)], r1, r2).result == "VIOLATION"


def test_inferred_pass_is_flagged_on_the_comparison():
    r1, r2 = NormalizedReport("t"), NormalizedReport("t")
    r1.add("A", K, PASS, "pass_inferred: no FAIL attributed"); r2.add("A", K, PASS, "pass_inferred: no FAIL attributed")
    a = check(_MR(), [("A", K)], r1, r2)
    assert a.key_results[0].inferred and a.to_json()["comparisons"][0]["basis"] == "inferred_pass"


# ---------------- P1-B MR-05 must not claim a subject/workload effect when another path still grants the permission
def test_mr05_second_role_for_same_sa_drops_subject_level_targets(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.objects += [_role("other", "lab-c", SECRETS_GET), _binding("other-b", "lab-c", "other", "reader")]
    mr = catalog["MR-05"]
    params = [p for p in mr.generate_parameters(src, 9) if p["role"][3] == "reader-role"][0]
    t = mr.targets(src, params)
    assert t["role_direct"] and "workload" not in t and "subject_sa" not in t and "bound_role" not in t


def test_mr05_clusterrolebinding_to_secret_reading_clusterrole_drops_targets(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.objects += [{"apiVersion": RB, "kind": "ClusterRole", "metadata": {"name": "cr"}, "rules": SECRETS_GET},
                    _binding("crb", "", "cr", "reader", kind="ClusterRole", bkind="ClusterRoleBinding")]
    mr = catalog["MR-05"]
    assert "workload" not in mr.targets(src, mr.generate_parameters(src, 1)[0])


def test_mr05_binding_to_unknown_builtin_clusterrole_is_treated_as_unsafe(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.objects.append(_binding("edit-b", "lab-c", "edit", "reader", kind="ClusterRole"))   # `edit` is not in the bundle
    mr = catalog["MR-05"]
    assert "workload" not in mr.targets(src, mr.generate_parameters(src, 1)[0])


def _extra_subject_binding(subject):
    return {"apiVersion": RB, "kind": "RoleBinding", "metadata": {"name": "grp-b", "namespace": "lab-c"},
            "subjects": [subject], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "other"}}


def test_mr05_secret_read_via_service_account_group_or_user_form_drops_targets(catalog, seed):
    for subject in ({"kind": "Group", "name": "system:serviceaccounts:lab-c"},
                    {"kind": "User", "name": "system:serviceaccount:lab-c:reader"},
                    {"kind": "Group", "name": "system:authenticated"}):
        src = seed("rbac-secrets-reader")
        src.objects += [_role("other", "lab-c", SECRETS_GET), _extra_subject_binding(subject)]
        mr = catalog["MR-05"]
        p = [x for x in mr.generate_parameters(src, 9) if x["role"][3] == "reader-role"][0]
        assert "workload" not in mr.targets(src, p), subject


def test_mr05_group_of_another_namespace_does_not_count(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.objects += [_role("other", "lab-c", SECRETS_GET), _extra_subject_binding({"kind": "Group", "name": "system:serviceaccounts:elsewhere"})]
    mr = catalog["MR-05"]
    p = [x for x in mr.generate_parameters(src, 9) if x["role"][3] == "reader-role"][0]
    assert mr.targets(src, p)["workload"]


def test_mr05_harmless_extra_role_keeps_workload_targets(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.objects += [_role("cm", "lab-c", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]),
                    _binding("cm-b", "lab-c", "cm", "reader")]
    mr = catalog["MR-05"]
    assert mr.targets(src, mr.generate_parameters(src, 1)[0])["workload"]


def test_mr05_with_other_grant_has_no_kubescape_scope_but_keeps_trivy_scope(catalog, seed, mapping):
    from k8s_mr_lab.checker import static_keys
    src = seed("rbac-secrets-reader")
    src.objects += [_role("other", "lab-c", SECRETS_GET), _binding("other-b", "lab-c", "other", "reader")]
    mr = catalog["MR-05"]
    p = [x for x in mr.generate_parameters(src, 9) if x["role"][3] == "reader-role"][0]
    assert static_keys(mr, mapping.entries("MR-05", "kubescape"), mapping.control_kinds("kubescape"), src, p) == []
    assert static_keys(mr, mapping.entries("MR-05", "trivy"), mapping.control_kinds("trivy"), src, p)


# ---------------- P1-C MR-04 must modify exactly the container named by the parameters
def test_mr04_wrong_container_index_is_invalid_pair(catalog, seed):
    mr, src = catalog["MR-04"], seed("pod-basic")
    params = {"workload": ["", "Pod", "lab-a", "demo"], "container_index": 0}
    fu = src.clone()
    fu.objects[0]["spec"]["containers"][1]["securityContext"]["privileged"] = True      # container 1, not 0
    assert mr.validate_pair(src, fu, params)[0] == "INVALID_PAIR"


def test_mr04_correct_container_index_is_valid(catalog, seed):
    mr, src = catalog["MR-04"], seed("pod-basic")
    params = {"workload": ["", "Pod", "lab-a", "demo"], "container_index": 1}
    fu, _ = mr.transform(src, params)
    assert mr.validate_pair(src, fu, params)[0] == "VALID_PAIR"


# ---------------- MR-03 the split must be exactly the requested one
def test_mr03_extra_rule_alongside_split_is_invalid(catalog, seed):
    mr, src = catalog["MR-03"], seed("rbac-secrets-reader")
    params = mr.generate_parameters(src, 1)[0]
    fu, _ = mr.transform(src, params)
    fu.find("Role", "lab-c", "reader-role")["rules"].append(                      # redundant duplicate: tuples unchanged
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]})
    assert mr.validate_pair(src, fu, params)[0] == "INVALID_PAIR"


# ---------------- P1-D scanner exit codes, P2-A policy identity
def _cfg(tmp_path, **over):
    (tmp_path / "tc/policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tc/policy/metadata.json").write_text(json.dumps({"Digest": "sha256:aaa"}))
    return {"trivy": {"binary": "trivy", "version": "0.75.0", "mode": "local-file", "timeout_s": 5,
                      "cache_dir": str(tmp_path / "tc"), "flags": ["config"], **over}}


def _fake(exit_code):
    def run(cmd, timeout, env):
        if "--version" in cmd:
            return 0, json.dumps({"Version": "0.75.0"}), ""
        Path(cmd[cmd.index("--output") + 1]).write_text("{}")
        return exit_code, "", "boom"
    return run


def test_nonzero_exit_with_valid_json_is_scan_error(tmp_path):
    inv = make_scanner("trivy", _cfg(tmp_path), _fake(3)).execute(tmp_path, tmp_path / "o.json")
    assert not inv.ok and "exit code 3" in inv.error


def test_exit_zero_is_accepted_and_accepted_codes_are_configurable(tmp_path):
    assert make_scanner("trivy", _cfg(tmp_path), _fake(0)).execute(tmp_path, tmp_path / "o.json").ok
    assert make_scanner("trivy", _cfg(tmp_path, accepted_exit_codes=[0, 3]), _fake(3)).execute(tmp_path, tmp_path / "o.json").ok


def test_unknown_policy_digest_is_scan_error_not_a_comparable_environment(tmp_path):
    cfg = _cfg(tmp_path)
    (tmp_path / "tc/policy/metadata.json").unlink()
    inv = make_scanner("trivy", cfg, _fake(0)).execute(tmp_path, tmp_path / "o.json")
    assert not inv.ok and "policy digest unavailable" in inv.error


def test_kubescape_missing_policy_file_gives_unknown_digest(tmp_path):
    cfg = {"kubescape": {"binary": "kubescape", "version": "v4.0.15", "mode": "local-file", "artifacts_dir": str(tmp_path),
                         "framework": "allcontrols"}}
    (tmp_path / "allcontrols.json").write_text("{}")          # controls-inputs.json and exceptions.json missing
    assert make_scanner("kubescape", cfg).policy_digest() == "unknown"
