"""MR-02 case study (docs/case_studies/MR02_SEMANTIC_CASE_STUDY.md): positive examples and counterexamples.

Each counterexample names the case-study section it backs. What these tests can NOT show (scanner semantics, the
closed-bundle premise) is argued in the document, not here.
"""
from __future__ import annotations

import copy

import pytest

from k8s_mr_lab.bundles import ConfigBundle, obj_key
from k8s_mr_lab.checker import check, static_keys
from k8s_mr_lab.k8s import RBAC
from k8s_mr_lab.model import FAIL, PASS, VALID_PAIR, NormalizedReport

DECOY_KIND = (RBAC, "Role")


# ------------------------------------------------------------------ positive examples (case study section 4)
@pytest.mark.parametrize("seed_name", ["rbac-workload", "rbac-secrets-reader", "K1-role-namespace"])
def test_positive_examples_every_profile_gives_a_valid_pair(catalog, seed, seed_name):
    mr = catalog["MR-02"]
    if seed_name == "K1-role-namespace":
        from conftest import ROOT
        from k8s_mr_lab.bundles import load_bundle
        src = load_bundle(ROOT / "seeds" / "historical" / seed_name, seed_name)
    else:
        src = seed(seed_name)
    before = copy.deepcopy(src.objects)
    params = mr.generate_parameters(src, 9)
    assert {p["profile"] for p in params} == {"secrets_read", "wildcard_admin"}
    for p in params:
        fu, trace = mr.transform(src, p)
        assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")
        assert trace["operation"] == "rbac.add_unbound_same_name_role"
    assert src.objects == before


# ------------------------------------------------------------------ counterexamples (case study section 5)
def _first(mr, src):
    return mr.generate_parameters(src, 9)[0]


def test_ce1_wrong_scope_decoy_in_an_existing_namespace_is_invalid(catalog, seed):
    """CE-1: putting the same-name Role into a namespace the source already uses can collide with, or sit next to, the
    target. The relation is then no longer 'unrelated resource', so the pair must be rejected."""
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = {**_first(mr, src), "decoy_namespace": "lab-a"}          # the target's own namespace
    fu, _ = mr.transform(src, p)
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


def test_ce2_binding_changed_retargeting_the_existing_binding_is_invalid(catalog, seed):
    """CE-2: if the follow-up also edits the RoleBinding (here: roleRef now points elsewhere), permissions change."""
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.find("RoleBinding", "lab-a", "app-binding")["subjects"][0]["namespace"] = p["decoy_namespace"]
    assert mr.validate_pair(src, fu, p) == ("INVALID_PAIR", "diff_is_not_exactly_one_added_object")


def test_ce3_extra_object_in_decoy_namespace_is_invalid(catalog, seed):
    """CE-3: a second object in the decoy namespace (e.g. a ServiceAccount a later binding could use) breaks isolation."""
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = _first(mr, src)
    fu, _ = mr.transform(src, p)
    fu.objects.append({"apiVersion": "v1", "kind": "ServiceAccount",
                       "metadata": {"name": "x", "namespace": p["decoy_namespace"]}})
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


def _bundle(rb_ref_kind: str, with_sa: bool = True) -> ConfigBundle:
    objs = [
        {"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": "r", "namespace": "ns"},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
        {"apiVersion": f"{RBAC}/v1", "kind": "ClusterRole", "metadata": {"name": "r"},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
        {"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": "b", "namespace": "ns"},
         "subjects": [{"kind": "ServiceAccount", "name": "sa", "namespace": "ns"}],
         "roleRef": {"apiGroup": RBAC, "kind": rb_ref_kind, "name": "r"}},
    ]
    if with_sa:
        objs.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sa", "namespace": "ns"}})
    return ConfigBundle(objs, "inline", "inline")


def test_ce4_rolebinding_to_a_clusterrole_is_not_applicable(catalog):
    """CE-4: roleRef.kind ClusterRole resolves cluster-wide by name, so the namespace argument of MR-02 does not apply."""
    assert catalog["MR-02"].applicable(_bundle("ClusterRole")) == (False, "no_rolebinding_to_local_role_with_sa_subject")
    assert catalog["MR-02"].applicable(_bundle("Role"))[0]


def test_ce5_subject_serviceaccount_missing_is_not_applicable(catalog):
    """CE-5: without the subject object in the bundle there is no identifiable target whose permissions are invariant."""
    assert catalog["MR-02"].applicable(_bundle("Role", with_sa=False)) == (False, "no_target_serviceaccount_object")


def test_ce6_findings_on_the_decoy_are_never_compared(catalog, seed, mapping):
    """CE-6: a Role-level control legitimately FAILs on the decoy (observed: Trivy KSV-0113 / KSV-0112 on
    Role/lab-a-decoy/app-role). The comparison scope must never contain the decoy."""
    mr, src = catalog["MR-02"], seed("rbac-workload")
    for p in mr.generate_parameters(src, 9):
        keys = static_keys(mr, mapping.entries("MR-02", "kubescape"), mapping.control_kinds("kubescape"), src, p)
        assert keys, "MR-02 must compare something"
        assert all(k[1][2] != p["decoy_namespace"] for k in keys)


def test_mr02_has_no_trivy_scope_and_says_why(mapping):
    """Every mapped Trivy check judges one Role document, so none can observe an added unrelated Role: the single mapping
    declares MR-02 unsupported for Trivy (with a reason) instead of comparing controls that cannot react."""
    assert mapping.entries("MR-02", "trivy") == [] and not mapping.supports("MR-02", "trivy")
    assert "judges one Role document" in mapping.data["unsupported"]["MR-02"]["trivy"]


def test_mr02_scope_is_the_subject_service_account_and_binding_not_only_the_role(mapping):
    """The property is the effective permissions of the target ServiceAccount; aggregator controls attach their verdict to the
    ServiceAccount and RoleBinding of the subject-role-binding triple (found with KD-001), so those are the compared targets."""
    got = {(e.control, e.target, e.role) for e in mapping.entries("MR-02", "kubescape")}
    for c in ("C-0015", "C-0007", "C-0035", "C-0053"):
        assert {(c, "subject_sa", "property"), (c, "rolebinding", "property")} <= got
    assert ("C-0057", "workload", "control") in got and not any(t == "bound_role" for _, t, _ in got)


def test_ce6_a_decoy_finding_alone_does_not_make_a_violation(catalog, seed, mapping):
    mr, src = catalog["MR-02"], seed("rbac-workload")
    p = [x for x in mr.generate_parameters(src, 9) if x["profile"] == "secrets_read"][0]
    fu, _ = mr.transform(src, p)
    keys = static_keys(mr, mapping.entries("MR-02", "kubescape"), mapping.control_kinds("kubescape"), src, p)
    r1, r2 = NormalizedReport("kubescape"), NormalizedReport("kubescape")
    for control, key in keys:
        r1.add(control, key, PASS)
        r2.add(control, key, PASS)
    decoy = next(obj_key(o) for o in fu.objects if obj_key(o)[2] == p["decoy_namespace"])
    r2.add("C-0015", decoy, FAIL, "alert on the decoy Role")      # a control may legitimately FAIL on the decoy; it is not compared
    assert check(mr, keys, r1, r2).result == "PASS"
