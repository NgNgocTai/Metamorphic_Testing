"""Normalizer golden tests: inputs are RAW reports captured from the real scanners (scripts/capture_golden.py)."""
import copy
import json
import random

from k8s_mr_lab.model import FAIL, NOT_EVALUATED, PASS
from k8s_mr_lab.normalize import kubescape as ks
from k8s_mr_lab.normalize import trivy as tv

ROLE_LAB_C = ("rbac.authorization.k8s.io", "Role", "lab-c", "reader-role")
DEPLOY_WEB = ("apps", "Deployment", "lab-a", "web")


def trivy_report(golden, mapping, name, raw=None):
    r, bundle, spans = golden("trivy", name)
    return tv.normalize(raw if raw is not None else r, bundle, spans, mapping.control_kinds("trivy"))


def ks_report(golden, name, raw=None):
    r, bundle, _ = golden("kubescape", name)
    return ks.normalize(raw if raw is not None else r, bundle)


def test_trivy_fail_is_attributed_by_line_to_the_right_resource(golden, mapping):
    rep = trivy_report(golden, mapping, "rbac-secrets-reader__source")
    assert rep.get("KSV-0113", ROLE_LAB_C).status == FAIL
    assert not rep.unattributed_failures


def test_trivy_decoy_failure_lands_on_the_decoy_not_the_target(golden, mapping):
    rep = trivy_report(golden, mapping, "rbac-workload__mr02-secrets_read")
    decoy = ("rbac.authorization.k8s.io", "Role", "lab-a-decoy", "app-role")
    target = ("rbac.authorization.k8s.io", "Role", "lab-a", "app-role")
    assert rep.get("KSV-0113", decoy).status == FAIL
    assert rep.get("KSV-0113", target).status == PASS      # inferred PASS: same name, different namespace


def test_trivy_pass_is_inference_and_says_so(golden, mapping):
    rep = trivy_report(golden, mapping, "rbac-workload__source")
    v = rep.get("KSV-0113", ("rbac.authorization.k8s.io", "Role", "lab-a", "app-role"))
    assert v.status == PASS and "pass_inferred" in v.evidence[0]


def test_ut08_trivy_finding_order_does_not_matter(golden, mapping):
    raw, _, _ = golden("trivy", "rbac-workload__mr02-wildcard_admin")
    shuffled = copy.deepcopy(raw)
    for res in shuffled["Results"]:
        random.Random(7).shuffle(res["Misconfigurations"])
    a = trivy_report(golden, mapping, "rbac-workload__mr02-wildcard_admin").to_json()
    b = trivy_report(golden, mapping, "rbac-workload__mr02-wildcard_admin", shuffled).to_json()
    assert a == b


def test_ut09_trivy_without_pass_entries_is_not_evaluated_never_pass(golden, mapping):
    raw, _, _ = golden("trivy", "rbac-workload__source")
    stripped = copy.deepcopy(raw)
    for res in stripped["Results"]:
        res["Misconfigurations"] = [m for m in res["Misconfigurations"] if m["Status"] != "PASS"]
    rep = trivy_report(golden, mapping, "rbac-workload__source", stripped)
    assert rep.get("KSV-0113", ("rbac.authorization.k8s.io", "Role", "lab-a", "app-role")).status == NOT_EVALUATED


def test_trivy_failure_outside_any_object_is_unattributed(golden, mapping):
    raw, _, _ = golden("trivy", "rbac-secrets-reader__source")
    bad = copy.deepcopy(raw)
    for m in bad["Results"][0]["Misconfigurations"]:
        if m["Status"] == "FAIL":
            m["CauseMetadata"]["StartLine"] = 9999
    assert trivy_report(golden, mapping, "rbac-secrets-reader__source", bad).unattributed_failures


def test_trivy_privileged_flip_is_visible_on_the_pod(golden, mapping):
    src = trivy_report(golden, mapping, "pod-basic__source")
    fu = trivy_report(golden, mapping, "pod-basic__mr04")
    pod = ("", "Pod", "lab-a", "demo")
    assert (src.get("KSV-0017", pod).status, fu.get("KSV-0017", pod).status) == (PASS, FAIL)
    assert fu.get("KSV-0017", ("", "Pod", "lab-a", "plain")).status == PASS


# ---------------- Kubescape
def test_kubescape_k1_signal_is_on_the_workload(golden):
    src = ks_report(golden, "rbac-workload__source")
    fu = ks_report(golden, "rbac-workload__mr02-secrets_read")
    assert (src.get("C-0267", DEPLOY_WEB).status, fu.get("C-0267", DEPLOY_WEB).status) == (PASS, FAIL)
    assert fu.get("C-0272", DEPLOY_WEB).status == PASS          # only the secrets profile, not the wildcard one


def test_kubescape_wildcard_decoy_flips_both_controls(golden):
    fu = ks_report(golden, "rbac-workload__mr02-wildcard_admin")
    assert fu.get("C-0267", DEPLOY_WEB).status == fu.get("C-0272", DEPLOY_WEB).status == FAIL


def test_kubescape_aggregated_rbac_result_covers_sa_role_and_binding(golden):
    raw, bundle, _ = golden("kubescape", "rbac-workload__source")
    agg = next(r["resourceID"] for r in raw["results"] if "ServiceAccount" in r["resourceID"] and "RoleBinding" in r["resourceID"])
    kinds = {k[1] for k in ks.members(agg, bundle)}
    assert kinds == {"ServiceAccount", "Role", "RoleBinding"}


def test_kubescape_unbound_decoy_role_has_no_verdict(golden):
    fu = ks_report(golden, "rbac-workload__mr02-secrets_read")
    decoy = ("rbac.authorization.k8s.io", "Role", "lab-a-decoy", "app-role")
    assert fu.get("C-0015", decoy).status == NOT_EVALUATED


def test_ut08_kubescape_result_order_does_not_matter(golden):
    raw, _, _ = golden("kubescape", "rbac-workload__mr02-secrets_read")
    shuffled = copy.deepcopy(raw)
    random.Random(3).shuffle(shuffled["results"])
    for r in shuffled["results"]:
        random.Random(5).shuffle(r["controls"])
    assert (ks_report(golden, "rbac-workload__mr02-secrets_read").to_json()
            == ks_report(golden, "rbac-workload__mr02-secrets_read", shuffled).to_json())


def test_ut09_kubescape_missing_control_is_not_evaluated(golden):
    raw, _, _ = golden("kubescape", "rbac-workload__source")
    cut = copy.deepcopy(raw)
    for r in cut["results"]:
        r["controls"] = [c for c in r["controls"] if c["controlID"] != "C-0267"]
    assert ks_report(golden, "rbac-workload__source", cut).get("C-0267", DEPLOY_WEB).status == NOT_EVALUATED


def test_kubescape_report_without_results_does_not_crash(golden):
    raw, bundle, _ = golden("kubescape", "rbac-no-binding__source")
    assert ks.normalize({}, bundle).verdicts == {}
