"""Reporting layer `informative`: classification is derived from the control's input model, never from the verdicts' history."""
from __future__ import annotations

import pytest

from conftest import ROOT
from k8s_mr_lab import informative as inf

ROLE = "Role/lab-a/app-role@rbac.authorization.k8s.io"
DECOY = "Role/lab-a-decoy/app-role@rbac.authorization.k8s.io"
BINDING = "RoleBinding/lab-a/app-binding@rbac.authorization.k8s.io"


def comp(control, resource, s, f, outcome="ok", basis="explicit"):
    return {"control": control, "resource": resource, "source": s, "followup": f, "outcome": outcome, "basis": basis, "reason": ""}


def test_input_model_comes_from_the_registry_derived_from_the_pinned_policy(mapping):
    reg = mapping.registry_controls()
    used = {sc: {e["control"] for per in mapping.data["mrs"].values() for e in per.get(sc) or []} for sc in ("trivy", "kubescape")}
    for scanner in ("trivy", "kubescape"):
        assert set(reg[scanner]) == used[scanner], scanner
    assert reg["trivy"]["KSV-0113"]["scope"] == "judged_object"
    assert "RoleBinding" in reg["kubescape"]["C-0267"]["reads"] and "RoleBinding" not in reg["kubescape"]["C-0057"]["reads"]


def test_trivy_check_sees_only_the_document_it_judges(mapping):
    # MR-02 adds a Role elsewhere: Trivy KSV-0113 on the (unchanged) bound Role cannot react ⇒ equal by construction
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "PASS", "PASS", basis="inferred_pass"), [DECOY], mapping)[0] == inf.UNINFORMATIVE
    # MR-04/05 change the judged object itself ⇒ observable
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "FAIL", "PASS"), [ROLE], mapping)[0] == inf.INFORMATIVE


def test_trivy_does_not_observe_a_rolebinding_change_so_mr07_is_uninformative_there(mapping):
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "FAIL", "FAIL"), [BINDING], mapping) == (inf.UNINFORMATIVE, "control cannot observe the changed object")


def test_kubescape_control_observes_every_kind_loaded_into_its_input(mapping):
    assert inf.classify("kubescape", comp("C-0267", "Deployment/lab-a/web@apps", "PASS", "PASS"), [BINDING], mapping)[0] == inf.INFORMATIVE
    assert inf.classify("kubescape", comp("C-0057", "Deployment/lab-a/web@apps", "PASS", "PASS"), [BINDING], mapping)[0] == inf.UNINFORMATIVE
    # C-0057 reads workloads only: adding a Role elsewhere cannot change it (this is why it is an MR-02 control experiment)
    assert inf.classify("kubescape", comp("C-0057", "Deployment/lab-a/web@apps", "PASS", "PASS"), [DECOY], mapping)[0] == inf.UNINFORMATIVE


def test_inferred_pass_is_weak_but_a_fail_is_positive_evidence(mapping):
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "PASS", "PASS", basis="inferred_pass"), [ROLE], mapping)[0] == inf.WEAK
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "FAIL", "FAIL", basis="inferred_pass"), [ROLE], mapping)[0] == inf.INFORMATIVE
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "FAIL", "PASS", "violation", "inferred_pass"), [ROLE], mapping)[0] == inf.INFORMATIVE


def test_missing_verdict_is_inconclusive_and_a_violation_on_an_unobservable_control_is_flagged(mapping):
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "NOT_EVALUATED", "PASS", "inconclusive"), [ROLE], mapping)[0] == inf.INCONCLUSIVE
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "PASS", "FAIL", "violation"), [DECOY], mapping) == (inf.UNINFORMATIVE, "UNEXPECTED_VIOLATION")


def test_representation_rewrite_with_an_empty_diff_counts_as_touching_everything(mapping):
    assert inf.changed_objects([]) == [inf.ALL]
    assert inf.classify("trivy", comp("KSV-0113", ROLE, "FAIL", "FAIL"), [inf.ALL], mapping)[0] == inf.INFORMATIVE


def test_unknown_control_is_an_error_not_a_silent_default(mapping):
    with pytest.raises(KeyError, match="no registry entry"):
        inf.classify("trivy", comp("KSV-9999", ROLE, "PASS", "PASS"), [ROLE], mapping)


EVIDENCE = ROOT / "docs" / "evidence" / "mr07_dev_2026-11-01"


def test_real_mr07_evidence_trivy_is_entirely_uninformative_and_kubescape_is_not(mapping):
    t = inf.analyze_run(EVIDENCE / "trivy", mapping)
    k = inf.analyze_run(EVIDENCE / "kubescape", mapping)
    assert t and {r["tier"] for r in t} == {inf.UNINFORMATIVE}
    assert {r["tier"] for r in k} == {inf.INFORMATIVE}
    assert [r["control"] for r in k if r["outcome"] == "violation"] == ["C-0267"]
    s = inf.summarize(t + k)
    assert s["all"]["trivy/ALL"]["informative_rate"] == 0.0 and s["unexpected_violations"] == []


def test_analysis_does_not_touch_the_saved_evidence(tmp_path, mapping):
    before = {p: p.read_bytes() for p in (EVIDENCE / "trivy").rglob("assessment.json")}
    inf.write_csv(inf.analyze_run(EVIDENCE / "trivy", mapping), tmp_path / "x.csv")
    assert {p: p.read_bytes() for p in before} == before and (tmp_path / "x.csv").exists()


def test_engaged_marks_weak_comparisons_where_a_fail_shows_the_check_reacts(mapping):
    e = ROOT / "docs" / "evidence" / "informative_2026-11-01"
    rows = inf.analyze_run(e / "trivy-run", mapping)
    weak = [r for r in rows if r["tier"] == inf.WEAK]
    assert weak, "Trivy MR-06 has an inferred PASS that turns into an attributed FAIL"
    assert all(r["engaged"] == ("FAIL" in (r["source"], r["followup"])) for r in rows)
    assert any(r["engaged"] for r in weak) and inf.summarize(rows)["weak_but_engaged"]


def test_negative_control_is_its_own_tier_and_a_violation_there_is_flagged(mapping):
    # MR-02 maps C-0057 as role: control (reads workloads only, cannot see an added Role)
    assert [(e.control, e.role) for e in mapping.entries("MR-02", "kubescape") if e.control == "C-0057"] == [("C-0057", "control")]
    c = comp("C-0057", "Deployment/lab-a/web@apps", "PASS", "PASS")
    assert inf.classify("kubescape", c, [DECOY], mapping, role="control") == (inf.CONTROL, "negative control stayed unchanged")
    v = comp("C-0057", "Deployment/lab-a/web@apps", "PASS", "FAIL", "violation")
    assert inf.classify("kubescape", v, [DECOY], mapping, role="control") == (inf.CONTROL, "UNEXPECTED_VIOLATION")
