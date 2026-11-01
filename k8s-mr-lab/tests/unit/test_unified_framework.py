"""The ONE framework: a single MR declaration, a single control mapping / scope resolution, a single pipeline.

Three groups of tests:
  * `check_mapping` rejects every inconsistency between catalog, mapping and control registry (no silent gap, orphan or mislabelled role)
  * architecture rules: core modules contain no MR-specific behaviour, there is exactly one execution path, no legacy mechanism remains
  * acceptance: a new MR needs only a catalog entry, a mapping entry and an implementation on the common interface
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from conftest import ROOT
from k8s_mr_lab import mr_tools
from k8s_mr_lab.bundles import ConfigBundle, obj_key
from k8s_mr_lab.checker import static_keys
from k8s_mr_lab.k8s import pod_spec
from k8s_mr_lab.model import ResKey, fmt_key
from k8s_mr_lab.registry import PolicyMapping, load_catalog, read_specs
from k8s_mr_lab.transforms.base import IMPLEMENTATIONS, implements, key_to_list, list_to_key
from k8s_mr_lab.transforms.patterns import Change, ControlledChange

CATALOG = ROOT / "mrs" / "catalog.yaml"
SRC = ROOT / "src" / "k8s_mr_lab"


def problems(mapping, specs=None, data=None, registry=None):
    m = PolicyMapping(data if data is not None else copy.deepcopy(mapping.data), registry if registry is not None else copy.deepcopy(mapping.registry))
    return mr_tools.check_mapping(specs if specs is not None else copy.deepcopy(read_specs(CATALOG)), m)


def has(ps, text):
    return any(text in p for p in ps)


# ------------------------------------------------------------------ the shipped declaration is consistent
def test_shipped_mapping_catalog_and_registry_are_consistent(mapping):
    assert problems(mapping) == []


def test_every_mr_scanner_pair_is_mapped_or_explained(mapping):
    for s in read_specs(CATALOG):
        for sc in ("trivy", "kubescape"):
            assert mapping.supports(s["id"], sc) != bool(((mapping.data.get("unsupported") or {}).get(s["id"]) or {}).get(sc)), (s["id"], sc)


# ------------------------------------------------------------------ check_mapping rejects each inconsistency
def test_silent_gap_is_rejected(mapping):
    d = copy.deepcopy(mapping.data)
    del d["unsupported"]["MR-08"]["trivy"]
    assert has(problems(mapping, data=d), "MR-08/trivy: neither mapped nor listed under unsupported with a reason")


def test_mapped_and_unsupported_at_once_is_rejected(mapping):
    d = copy.deepcopy(mapping.data)
    d["unsupported"]["MR-04"] = {"trivy": "no"}
    assert has(problems(mapping, data=d), "MR-04/trivy: mapped AND listed under unsupported")


def test_unknown_target_and_undeclared_target_are_rejected(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0]["target"] = "nowhere"
    assert has(problems(mapping, data=d), "MR-04/trivy/KSV-0017->nowhere: unknown target")
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0]["target"] = "bound_role"          # in the vocabulary, but MR-04 does not declare it
    assert has(problems(mapping, data=d), "target is not declared by the MR in the catalog")
    specs = copy.deepcopy(read_specs(CATALOG))
    specs[3]["targets"] = ["workload", "invented"]
    assert has(problems(mapping, specs=specs), "catalog target 'invented' is not in the mapping target vocabulary")


def test_all_of_kind_is_only_for_a_rewrite_of_every_object(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0]["target"] = "ALL_OF_KIND"
    ps = problems(mapping, data=d)
    assert has(ps, "ALL_OF_KIND is only for an MR whose touches is ['*']")
    specs = copy.deepcopy(read_specs(CATALOG))
    specs[0]["touches"] = ["Pod"]                                     # MR-01 no longer claims to rewrite everything
    assert has(problems(mapping, specs=specs), "touches ['*'] and targets [ALL_OF_KIND] go together")


def test_property_entry_must_be_able_to_observe_the_change(mapping):
    d = copy.deepcopy(mapping.data)
    # C-0057 reads workloads only; as a property comparison of an MR that changes a Role it can never react
    d["mrs"]["MR-02"]["kubescape"][-1]["role"] = "property"
    assert has(problems(mapping, data=d), "MR-02/kubescape/C-0057->workload: role property but the control cannot observe")


def test_negative_control_must_not_be_able_to_observe_the_change(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-02"]["kubescape"][0]["role"] = "control"            # C-0267 reads Roles, so it is a property comparison
    assert has(problems(mapping, data=d), "MR-02/kubescape/C-0267->workload: role control but the control can observe")


def test_trivy_judged_object_must_see_the_changed_object_itself(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0]["control"] = "KSV-0113"            # a Role check, while MR-04 changes workloads
    ps = problems(mapping, data=d)
    assert has(ps, "MR-04/trivy/KSV-0113->workload")


def test_unknown_control_orphan_registry_entry_and_bad_entry_are_rejected(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0]["control"] = "KSV-9999"
    assert has(problems(mapping, data=d), "MR-04/trivy/KSV-9999->workload: control is not in control-registry.yaml")
    reg = copy.deepcopy(mapping.registry)
    reg["controls"]["trivy"]["KSV-0999"] = copy.deepcopy(reg["controls"]["trivy"]["KSV-0017"])
    assert has(problems(mapping, registry=reg), "control-registry: trivy/KSV-0999 is not used by any mapping entry")
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"][0].pop("reason")
    assert has(problems(mapping, data=d), "needs non-empty control, target and reason")
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-04"]["trivy"].append({"control": "KSV-0017", "target": "workload", "role": "control", "reason": "x"})
    assert has(problems(mapping, data=d), "two different roles")


def test_mapping_for_an_mr_that_is_not_in_the_catalog_is_an_orphan(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-77"] = {"trivy": [], "kubescape": []}
    d["unsupported"]["MR-78"] = {"trivy": "x"}
    ps = problems(mapping, data=d)
    assert has(ps, "mapping lists unknown MR MR-77") and has(ps, "mapping lists unknown MR MR-78")


def test_dead_entry_whose_control_never_reports_on_the_target_kinds_is_rejected(mapping):
    d = copy.deepcopy(mapping.data)
    d["mrs"]["MR-03"]["trivy"][0]["target"] = "workload"             # MR-03 does not declare it either; and KSV-0113 never reports on it
    ps = problems(mapping, data=d)
    assert has(ps, "dead entry")


def test_runtime_target_not_declared_in_the_catalog_is_an_error(catalog, seed, mapping):
    mr = catalog["MR-04"]
    src = seed("pod-basic")
    p = mr.generate_parameters(src, 1)[0]
    mr.targets = lambda s, q: {"workload": [], "surprise": []}        # an implementation returning a selector it never declared
    try:
        with pytest.raises(ValueError, match="targets\\(\\) returned \\['surprise'\\]"):
            static_keys(mr, mapping.entries("MR-04", "trivy"), mapping.control_kinds("trivy"), src, p)
    finally:
        del mr.targets


def test_a_registry_from_other_policy_artifacts_is_detectable(mapping):
    reg = mapping.registry
    assert set(reg["derived_under"]) == {"trivy", "kubescape"} and all(reg["derived_under"].values())
    assert all(m["source_sha256"] and m["source"] for sc in reg["controls"].values() for m in sc.values())


# ------------------------------------------------------------------ one execution path, no MR logic in the core
CORE = [p for p in SRC.rglob("*.py") if "transforms" not in p.relative_to(SRC).parts]
MR_LITERAL = re.compile(r"""["']MR-\d{2,}["']""")
CONTROL_LITERAL = re.compile(r"""["'](KSV-\d{4}|C-\d{4})["']""")


def test_core_modules_contain_no_mr_or_control_specific_behaviour():
    offenders = [f"{p.relative_to(SRC)}:{i}" for p in CORE for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
                 if MR_LITERAL.search(line) or CONTROL_LITERAL.search(line)]
    assert offenders == []


def test_exactly_one_pipeline_executes_scanners_and_writes_assessments():
    users = lambda needle: sorted(p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py") if needle in p.read_text(encoding="utf-8"))
    assert [f for f in users(".execute(") if not f.startswith("scanners/")] == ["runner.py"]
    writers = [f for f in users('"assessment.json"') if '"assessment.json").write_text' in (SRC / f).read_text(encoding="utf-8")
               or '"assessment.json", "assessment.json"' in (SRC / f).read_text(encoding="utf-8")]
    assert writers == ["runner.py", "triage.py"]                     # runner writes it; triage only copies it into a reproducer
    assert users("check(mr,") == ["runner.py"]                       # the one place the relation oracle is applied to a case
    assert users("annotate(") == ["informative.py", "runner.py"]


def test_no_legacy_mapping_checker_or_input_model_remains():
    assert not (ROOT / "config" / "control-inputs.yaml").exists() and not (ROOT / "scripts" / "derive_control_inputs.py").exists()
    for p in [*SRC.rglob("*.py"), *(ROOT / "scripts").glob("*.py")]:
        text = p.read_text(encoding="utf-8")
        assert "control_inputs" not in text and "control-inputs" not in text, p
        assert "legacy" not in text.lower(), p
    cfg = (ROOT / "config" / "policy-mapping.yaml").read_text(encoding="utf-8")
    assert "schema: mr-mapping/1" in cfg and "\ncontrols:" not in cfg      # what a control reads lives only in the registry


def test_every_mr_uses_the_same_declaration_fields():
    specs = read_specs(CATALOG)
    assert {frozenset(s) - {"all_failures"} for s in specs} == {frozenset(specs[0]) - {"all_failures"}}
    assert len(specs) == len(load_catalog(CATALOG)) == len(IMPLEMENTATIONS)


# ------------------------------------------------------------------ acceptance: a new MR needs no change to the core
HOST_PID = {
    "id": "MR-10", "name": "host-pid-flip", "category": "R02", "status": "candidate", "pattern": "KP3",
    "property_id": "SP-POD-HOST-NAMESPACES", "property": "enabling hostPID on a workload must be flagged",
    "relation": "pass_to_fail", "scope": "the mutated workload",
    "preconditions": ["workload with spec.hostPID explicitly false"], "transformation": "set spec.hostPID true on one workload",
    "pair_checks": ["only spec.hostPID changed"], "counterexample": "workload without an explicit hostPID",
    "limits": ["only hostPID"], "template": {"preconditions": ["P-STRUCT"], "followup": ["G-MODIFY"]},
    "origin": "retrospective", "requirements": [{"id": "R02", "coverage": "partial"}], "touches": ["workload"], "targets": ["workload"]}


def _host_pid_class():
    @implements("MR-10")
    class HostPidFlip(ControlledChange):
        no_candidates_reason = "no_workload_with_explicit_hostpid_false"

        def candidates(self, source: ConfigBundle) -> list[dict]:
            return [o for o in source.objects if (ps := pod_spec(o)) and ps[1].get("hostPID") is False]

        def candidate_params(self, candidate: dict) -> dict:
            return {"workload": key_to_list(obj_key(candidate))}

        def transform(self, source: ConfigBundle, params: dict):
            fu = source.clone()
            pod_spec(fu.index()[list_to_key(params["workload"])])[1]["hostPID"] = True
            return fu, {"operation": "pod.set_host_pid_true", "workload": fmt_key(list_to_key(params["workload"]))}

        def expected_change(self, source: ConfigBundle, params: dict) -> Change | None:
            key = list_to_key(params["workload"])
            wl = source.index().get(key)
            return Change(key, ".".join(pod_spec(wl)[0]) + ".hostPID", False, True) if wl is not None and pod_spec(wl) else None

        def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
            return {"workload": [list_to_key(params["workload"])]}
    return HostPidFlip


@pytest.fixture()
def new_mr(tmp_path, mapping):
    """MR-10 exists only for this test: one catalog entry, one mapping entry, one class. Nothing else is touched."""
    cls = _host_pid_class()
    specs = copy.deepcopy(read_specs(CATALOG)) + [copy.deepcopy(HOST_PID)]
    import yaml
    cat = tmp_path / "catalog.yaml"
    cat.write_text(yaml.safe_dump({"mrs": specs}), encoding="utf-8")
    data = copy.deepcopy(mapping.data)
    data["mrs"]["MR-10"] = {"trivy": [{"control": "KSV-0009", "target": "workload", "reason": "judges spec.hostNetwork, not hostPID"}],
                            "kubescape": [{"control": "C-0041", "target": "workload", "reason": "judges hostNetwork, not hostPID"}]}
    yield cat, PolicyMapping(data, mapping.registry), specs
    del IMPLEMENTATIONS["MR-10"]


def test_a_new_mr_is_accepted_through_the_common_interface_only(new_mr, seed):
    cat, mapping, specs = new_mr
    catalog = load_catalog(cat)
    assert mr_tools.check_mapping(specs, mapping) == []
    mr = catalog["MR-10"]
    src = seed("pod-basic")
    ok, why = mr.applicable(src)
    errs, warns, cases = mr_tools.exercise(mr, [ROOT / "seeds/synthetic/pod-basic"], mapping)
    assert ok or why == "no_workload_with_explicit_hostpid_false"
    assert errs == []
    keys = []
    for p in mr.generate_parameters(src, 3):
        keys += static_keys(mr, mapping.entries("MR-10", "trivy"), mapping.control_kinds("trivy"), src, p)
    assert all(c == "KSV-0009" for c, _ in keys)


def test_a_new_mr_with_an_unexplained_scanner_gap_is_rejected(new_mr):
    _, mapping, specs = new_mr
    d = copy.deepcopy(mapping.data)
    del d["mrs"]["MR-10"]["kubescape"]
    assert has(mr_tools.check_mapping(specs, PolicyMapping(d, mapping.registry)), "MR-10/kubescape: neither mapped nor listed under unsupported")


# ------------------------------------------------------------------ provenance and per-comparison annotation
def test_run_lock_records_experiment_provenance(tmp_path, catalog, mapping):
    from test_runner import make
    from k8s_mr_lab.experiment import provenance
    runner, _, _ = make(tmp_path, catalog, mapping, "kubescape")
    seeds = [ROOT / "seeds/synthetic/rbac-workload"]
    p = provenance(experiment_type="baseline", experiment_id="exp-x", scope_profile="official", catalog_path=str(CATALOG),
                   mapping_path=str(ROOT / "config/policy-mapping.yaml"), seed_dirs=seeds, runner=runner, mr_ids=["MR-02"])
    assert p["experiment_id"] == "exp-x" and p["experiment_type"] == "baseline" and p["scope_profile"] == "official"
    assert p["schema"]["mapping"] == "mr-mapping/1" and len(p["seed_digest"]) == 64 and p["included_mrs"] == [{"id": "MR-02", "status": "mvp"}]
    assert all(len(p["digests"][k]) == 64 for k in ("catalog", "requirements", "properties", "mapping", "control_registry"))
    assert p["registry_matches_policy"] is False                      # the replay scanner has another policy digest than the registry
    with pytest.raises(ValueError, match="experiment type"):
        provenance(experiment_type="other", experiment_id=None, scope_profile="x", catalog_path=str(CATALOG),
                   mapping_path=str(ROOT / "config/policy-mapping.yaml"), seed_dirs=seeds, runner=runner, mr_ids=None)


def test_every_comparison_carries_role_and_tier_from_the_one_pipeline(tmp_path, catalog, mapping):
    from test_runner import case, make
    runner, _, _ = make(tmp_path, catalog, mapping, "kubescape")
    r = case(runner, catalog, "rbac-workload", "MR-02", lambda p: p["profile"] == "secrets_read")
    comps = r.assessment.to_json()["comparisons"]
    assert comps and all(c["tier"] and c["role"] in ("property", "control") for c in comps)
    assert {c["control"] for c in comps if c["role"] == "control"} <= {"C-0057"}
    assert all(c["tier"] == "CONTROL" for c in comps if c["role"] == "control")
    assert any(c["tier"] == "INFORMATIVE" and c["engaged"] for c in comps)           # C-0267 PASS -> FAIL on the workload


# ------------------------------------------------------------------ control scope rule (MR-01 on aggregator controls) and verdict availability
from k8s_mr_lab.checker import check, full_keys, static_keys as _sk  # noqa: E402
from k8s_mr_lab.model import FAIL, NOT_EVALUATED, PASS, NormalizedReport  # noqa: E402

AGG = "C-0015"
SA_BOUND = ("", "ServiceAccount", "lab-a", "app")
SA_LONE = ("", "ServiceAccount", "lab-a", "lonely")
RB = ("rbac.authorization.k8s.io", "RoleBinding", "lab-a", "app-binding")
ROLE_LONE = ("rbac.authorization.k8s.io", "Role", "lab-a", "unbound")


def _scoped(mapping, catalog, seed, extra=None):
    src = seed("rbac-workload")
    for o in extra or []:
        src.objects.append(o)
    mr = catalog["MR-01"]
    ex: list = []
    keys = _sk(mr, mapping.entries("MR-01", "kubescape"), mapping.control_kinds("kubescape"), src, {}, mapping.scope_rules("kubescape"), ex)
    return mr, src, keys, ex


def test_unbound_objects_are_outside_an_aggregator_scope_bound_ones_are_inside(mapping, catalog, seed):
    lone_sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "lonely", "namespace": "lab-a"}}
    lone_role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "unbound", "namespace": "lab-a"}, "rules": []}
    _, _, keys, ex = _scoped(mapping, catalog, seed, [lone_sa, lone_role])
    got = {k for c, k in keys if c == AGG}
    assert {SA_BOUND, RB} <= got and SA_LONE not in got and ROLE_LONE not in got        # 3 and 4 below stay compared, unrelated ones do not
    assert {(c, k) for c, k, r in ex if c == AGG} >= {(AGG, SA_LONE), (AGG, ROLE_LONE)} and {r for _, _, r in ex} == {"rbac_triple_member"}
    assert ("C-0267", SA_LONE) not in keys and not any(c == "C-0057" and k[1] in ("ServiceAccount", "Role") for c, k in keys)


def _reports(a, b):
    r1, r2 = NormalizedReport("kubescape"), NormalizedReport("kubescape")
    for (rep, v) in ((r1, a), (r2, b)):
        for k in (SA_BOUND,):
            rep.add(AGG, k, v)
    return r1, r2


@pytest.mark.parametrize("a,b,result", [
    (PASS, PASS, "PASS"),                      # verdict on both sides and equal
    (PASS, FAIL, "VIOLATION"),                 # verdict on both sides and different: scope filtering must not hide it
    (PASS, NOT_EVALUATED, "INCONCLUSIVE"),     # in scope, source has a verdict, follow-up lost it
    (NOT_EVALUATED, PASS, "INCONCLUSIVE"),     # follow-up has a verdict, source missing
    (NOT_EVALUATED, NOT_EVALUATED, "INCONCLUSIVE"),   # in scope but the scanner evaluated neither side: stays visible, never PASS
])
def test_verdict_availability_on_an_in_scope_key_is_never_hidden(mapping, catalog, seed, a, b, result):
    mr, src, keys, _ = _scoped(mapping, catalog, seed)
    r1, r2 = _reports(a, b)
    only = [(c, k) for c, k in keys if (c, k) == (AGG, SA_BOUND)]
    assert only
    assert check(mr, only, r1, r2).result == result


def test_a_fail_outside_the_resolved_scope_is_still_compared_by_all_failures(mapping, catalog, seed):
    mr, src, keys, _ = _scoped(mapping, catalog, seed)
    r1, r2 = NormalizedReport("kubescape"), NormalizedReport("kubescape")
    r1.add(AGG, SA_LONE, FAIL)
    r2.add(AGG, SA_LONE, PASS)                 # an unrelated resource's finding changes: MR-01 (all_failures) must still see it
    full = full_keys(mr, keys, r1, r2)
    assert (AGG, SA_LONE) in full


def test_unknown_scope_rule_in_the_registry_is_rejected(mapping):
    reg = copy.deepcopy(mapping.registry)
    reg["controls"]["kubescape"]["C-0015"]["scope_rule"] = "nope"
    assert has(problems(mapping, registry=reg), "unknown scope_rule 'nope'")


def test_registry_declares_the_rule_for_exactly_the_aggregator_controls(mapping):
    for sc, ctl in mapping.registry["controls"].items():
        for c, m in ctl.items():
            assert bool(m.get("scope_rule")) == bool(m.get("aggregator")), (sc, c)
