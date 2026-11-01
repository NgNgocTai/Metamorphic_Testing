"""Per-MR: positive case, counterexample, and 'source is never mutated'."""
import copy

from k8s_mr_lab.bundles import obj_key
from k8s_mr_lab.model import VALID_PAIR
from k8s_mr_lab.validation import diff_bundles


def _first(mr, src):
    return mr.generate_parameters(src, 9)[0]


def test_catalog_matches_code(catalog):
    # the five frozen PoC MRs, plus MR-06 / MR-07 which are candidates and are not part of the PoC baseline
    assert sorted(m for m, mr in catalog.items() if mr.spec["status"] != "candidate") == ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05"]
    assert sorted(catalog) == ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05", "MR-06", "MR-07"]
    for mr in catalog.values():
        assert mr.spec["preconditions"] and mr.spec["counterexample"] and mr.spec["limits"]


# ---------------- MR-01
def test_mr01_positive_and_source_untouched(catalog, seed):
    mr, src = catalog["MR-01"], seed("rbac-workload")
    before = copy.deepcopy(src.objects)
    for p in mr.generate_parameters(src, 9):
        fu, _ = mr.transform(src, p)
        assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")
    assert src.objects == before


def test_mr01_counterexample_changed_content_is_invalid(catalog, seed):
    mr, src = catalog["MR-01"], seed("pod-basic")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.objects[0]["spec"]["containers"].reverse()           # reordering a sequence is NOT a valid MR-01 step
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


# ---------------- MR-02
def test_ut03_mr02_adds_exactly_one_unbound_role(catalog, seed):
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    d = diff_bundles(src, fu)
    assert [x["op"] for x in d] == ["add_object"] and "Role/" in d[0]["object"]
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")
    assert len(fu.of_kind("RoleBinding")) == len(src.of_kind("RoleBinding"))
    added = [o for o in fu.objects if obj_key(o)[2] == p["decoy_namespace"]]
    assert len(added) == 1 and added[0]["metadata"]["name"] == p["role"]


def test_ut04_mr02_skips_without_local_rolebinding(catalog, seed):
    ok, why = catalog["MR-02"].applicable(seed("rbac-no-binding"))
    assert not ok and why == "no_rolebinding"


def test_mr02_counterexample_extra_binding_is_invalid(catalog, seed):
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                       "metadata": {"name": "x", "namespace": p["decoy_namespace"]},
                       "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "lab-a"}],
                       "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": p["role"]}})
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


def test_mr02_decoy_namespace_is_fresh(catalog, seed):
    src = seed("rbac-workload")
    for p in catalog["MR-02"].generate_parameters(src, 9):
        assert p["decoy_namespace"] not in {obj_key(o)[2] for o in src.objects}


def test_mr02_targets_exclude_the_decoy(catalog, seed):
    mr, src = catalog["MR-02"], seed("rbac-workload")
    t = mr.targets(src, _first(mr, src))
    assert t["bound_role"] == [("rbac.authorization.k8s.io", "Role", "lab-a", "app-role")]
    assert t["workload"] == [("apps", "Deployment", "lab-a", "web")]


# ---------------- MR-03
def test_ut05_mr03_preserves_permissions_and_source(catalog, seed):
    mr, src = catalog["MR-03"], seed("rbac-secrets-reader")
    before = copy.deepcopy(src.objects)
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    assert src.objects == before
    role = fu.find("Role", "lab-c", "reader-role")
    assert [r["verbs"] for r in role["rules"]] == [["get"], ["list"], ["watch"]]
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")


def test_mr03_counterexample_permissions_changed_is_invalid(catalog, seed):
    mr, src = catalog["MR-03"], seed("rbac-secrets-reader")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.find("Role", "lab-c", "reader-role")["rules"][1]["resources"] = ["configmaps"]
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


def test_mr03_not_applicable_to_single_verb_rules(catalog, seed):
    assert not catalog["MR-03"].applicable(seed("rbac-workload"))[0]


# ---------------- MR-04
def test_ut06_mr04_changes_exactly_one_field(catalog, seed):
    mr, src = catalog["MR-04"], seed("pod-basic")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    d = diff_bundles(src, fu)
    assert len(d) == 1 and d[0]["path"].endswith("securityContext.privileged") and (d[0]["old"], d[0]["new"]) == (False, True)
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")


def test_mr04_needs_explicit_privileged_false(catalog, seed):
    assert not catalog["MR-04"].applicable(seed("rbac-basic"))[0]
    pods = seed("pod-basic")
    params = catalog["MR-04"].generate_parameters(pods, 9)
    assert {p["workload"][3] for p in params} == {"demo"}        # 'plain' has no explicit privileged: excluded


def test_mr04_counterexample_second_change_is_invalid(catalog, seed):
    mr, src = catalog["MR-04"], seed("pod-basic")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.objects[0]["spec"]["containers"][1]["image"] = "evil:1"
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


# ---------------- MR-05
def test_ut07_mr05_changes_only_the_api_group(catalog, seed):
    mr, src = catalog["MR-05"], seed("rbac-secrets-reader")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    d = diff_bundles(src, fu)
    assert len(d) == 1 and d[0]["path"] == "rules[0].apiGroups[0]" and d[0]["new"] == "apps"
    assert fu.find("RoleBinding", "lab-c", "reader-binding") == src.find("RoleBinding", "lab-c", "reader-binding")
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")


def test_mr05_counterexample_second_rule_makes_role_ineligible(catalog, seed):
    mr, src = catalog["MR-05"], seed("rbac-secrets-reader")
    src.find("Role", "lab-c", "reader-role")["rules"].append(
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]})   # wildcard keeps the permission alive
    assert not mr.applicable(src)[0]


def test_mr05_requires_core_secrets_read_only(catalog, seed):
    src = seed("rbac-secrets-reader")
    src.find("Role", "lab-c", "reader-role")["rules"][0]["verbs"].append("delete")
    assert not catalog["MR-05"].applicable(src)[0]


# ---------------- MR-07 (candidate): ServiceAccount subject rewritten as the equivalent User subject
def test_mr07_positive_rewrites_exactly_one_subject(catalog, seed):
    mr, src = catalog["MR-07"], seed("rbac-secrets-reader")
    before = copy.deepcopy(src.objects)
    (p,) = mr.generate_parameters(src, 9)
    fu, trace = mr.transform(src, p)
    assert src.objects == before
    assert fu.find("RoleBinding", "lab-c", "reader-binding")["subjects"] == [
        {"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:serviceaccount:lab-c:reader"}]
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")
    assert mr.targets(src, p)["workload"] == [("", "Pod", "lab-c", "reader-pod")]


def test_mr07_counterexample_group_subject_is_not_equivalent(catalog, seed):
    mr, src = catalog["MR-07"], seed("rbac-secrets-reader")
    (p,) = mr.generate_parameters(src, 9)
    fu, _ = mr.transform(src, p)
    fu.find("RoleBinding", "lab-c", "reader-binding")["subjects"] = [
        {"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:serviceaccounts:lab-c"}]
    assert mr.validate_pair(src, fu, p) == ("INVALID_PAIR", "subject_is_not_the_equivalent_user")


def test_mr07_counterexample_user_of_another_namespace_is_not_equivalent(catalog, seed):
    mr, src = catalog["MR-07"], seed("rbac-secrets-reader")
    (p,) = mr.generate_parameters(src, 9)
    fu, _ = mr.transform(src, p)
    fu.find("RoleBinding", "lab-c", "reader-binding")["subjects"][0]["name"] = "system:serviceaccount:other:reader"
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


def test_mr07_counterexample_other_binding_change_is_invalid(catalog, seed):
    mr, src = catalog["MR-07"], seed("rbac-secrets-reader")
    (p,) = mr.generate_parameters(src, 9)
    fu, _ = mr.transform(src, p)
    fu.find("RoleBinding", "lab-c", "reader-binding")["roleRef"]["name"] = "something-else"
    assert mr.validate_pair(src, fu, p) == ("INVALID_PAIR", "rolebinding_changed_beyond_the_subject")


def test_mr07_requires_explicit_subject_namespace_and_present_sa(catalog, seed):
    src = seed("rbac-secrets-reader")
    del src.find("RoleBinding", "lab-c", "reader-binding")["subjects"][0]["namespace"]
    assert not catalog["MR-07"].applicable(src)[0]
    assert not catalog["MR-07"].applicable(seed("rbac-no-binding"))[0]
