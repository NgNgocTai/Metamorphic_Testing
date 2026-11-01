"""MR construction framework: spec schema, traceability, patterns, MR-06 (worked example), authoring CLI."""
from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from conftest import ROOT
from k8s_mr_lab import checker, mr_tools
from k8s_mr_lab.bundles import ConfigBundle
from k8s_mr_lab.model import VALID_PAIR, fmt_key
from k8s_mr_lab.registry import PolicyMapping, active_mrs, load_catalog, read_specs
from k8s_mr_lab.transforms.base import IMPLEMENTATIONS, MetamorphicRelation, implements
from k8s_mr_lab.validation import diff_bundles, expect_single_change

CATALOG = ROOT / "mrs" / "catalog.yaml"
PROPS = ROOT / "mrs" / "security_properties.yaml"
PATS = ROOT / "mrs" / "patterns.yaml"


def specs_copy():
    return copy.deepcopy(read_specs(CATALOG))


def write_catalog(tmp_path, specs) -> Path:
    p = tmp_path / "catalog.yaml"
    p.write_text(yaml.safe_dump({"mrs": specs}), encoding="utf-8")
    return p


def trace_problems(specs, props=None, pats=None, mapping=None):
    return mr_tools.check_traceability(specs, props or mr_tools.load_properties(PROPS), pats or mr_tools.load_patterns(PATS),
                                       mapping or PolicyMapping.load(ROOT / "config" / "policy-mapping.yaml"))


# ------------------------------------------------------------------ MR specification
def test_shipped_catalog_is_consistent(mapping):
    assert trace_problems(read_specs(CATALOG), mapping=mapping) == []


def test_spec_missing_required_field(tmp_path):
    specs = specs_copy()
    del specs[0]["pattern"]
    with pytest.raises(ValueError, match="MR-01: missing required field.*pattern"):
        read_specs(write_catalog(tmp_path, specs))


def test_spec_duplicate_mr_id(tmp_path):
    specs = specs_copy()
    specs.append(copy.deepcopy(specs[0]))
    with pytest.raises(ValueError, match="duplicate MR id MR-01"):
        read_specs(write_catalog(tmp_path, specs))


@pytest.mark.parametrize("field,value,msg", [("relation", "sometimes", "unknown relation"), ("status", "done", "unknown status")])
def test_spec_invalid_enum(tmp_path, field, value, msg):
    specs = specs_copy()
    specs[0][field] = value
    with pytest.raises(ValueError, match=msg):
        read_specs(write_catalog(tmp_path, specs))


def test_catalog_entry_without_implementation_fails_loudly(tmp_path):
    specs = specs_copy()
    ghost = copy.deepcopy(specs[0])
    ghost["id"] = "MR-99"
    with pytest.raises(ValueError, match="MR-99 without an @implements"):
        load_catalog(write_catalog(tmp_path, specs + [ghost]))


def test_implementation_without_catalog_entry_fails_loudly(tmp_path):
    @implements("MR-98")
    class _Orphan(MetamorphicRelation):
        pass
    try:
        with pytest.raises(ValueError, match="implemented but missing from catalog: \\['MR-98'\\]"):
            load_catalog(CATALOG)
    finally:
        del IMPLEMENTATIONS["MR-98"]


def test_implementing_the_same_id_twice_is_rejected():
    with pytest.raises(ValueError, match="implemented twice"):
        @implements("MR-01")
        class _Dup(MetamorphicRelation):
            pass


def test_unknown_pattern_and_property_and_disallowed_relation(mapping):
    specs = specs_copy()
    specs[0]["pattern"] = "KP9"
    specs[1]["property_id"] = "SP-NOPE"
    specs[3]["relation"] = "equal"                     # KP3 only allows pass_to_fail / fail_to_pass
    problems = trace_problems(specs, mapping=mapping)
    assert any("MR-01: unknown pattern KP9" in p for p in problems)
    assert any("MR-02: unknown property SP-NOPE" in p for p in problems)
    assert any("MR-04: relation equal not allowed by pattern KP3" in p for p in problems)


def test_pattern_must_be_a_candidate_of_the_property(mapping):
    specs = specs_copy()
    specs[3]["pattern"] = "KP1"                        # MR-04's property only lists KP3
    assert any("not a candidate pattern of SP-POD-PRIVILEGED" in p for p in trace_problems(specs, mapping=mapping))


def test_reference_without_verified_flag_is_rejected(mapping):
    props = copy.deepcopy(mr_tools.load_properties(PROPS))
    del props[1]["owasp_k8s_2025"][0]["verified"]
    assert any("without boolean 'verified'" in p for p in trace_problems(read_specs(CATALOG), props=props, mapping=mapping))


def test_unsupported_scanner_control_mapping_is_rejected():
    data = copy.deepcopy(PolicyMapping.load(ROOT / "config" / "policy-mapping.yaml").data)
    data["mrs"]["MR-04"]["trivy"].append({"control": "KSV-9999", "target": "workload"})
    data["mrs"]["MR-77"] = {"trivy": []}
    problems = trace_problems(read_specs(CATALOG), mapping=PolicyMapping(data))
    assert any("MR-04/trivy: mapped control KSV-9999" in p for p in problems)
    assert any("policy-mapping lists unknown MR MR-77" in p for p in problems)


def test_candidate_is_skipped_unless_named(catalog):
    assert [m.id for m in active_mrs(catalog)] == ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05"]
    assert [m.id for m in active_mrs(catalog, ["MR-06"])] == ["MR-06"]


def test_metadata_has_a_single_source(catalog):
    for mr in catalog.values():
        assert not {"name", "category", "relation", "property"} & set(type(mr).__dict__), type(mr).__name__
        assert (mr.name, mr.category, mr.relation) == (mr.spec["name"], mr.spec["category"], mr.spec["relation"])


# ------------------------------------------------------------------ patterns / primitives
def _change_diff(old, new, path="spec.x"):
    return [{"op": "change", "path": path, "old": old, "new": new, "object": "Pod/ns/p"}]


KEY = ("", "Pod", "ns", "p")


def test_expect_single_change_accepts_exactly_the_declared_change():
    assert expect_single_change(_change_diff(False, True), KEY, "spec.x", False, True) == (VALID_PAIR, "")


@pytest.mark.parametrize("diff,reason", [
    ([], "expected_exactly_one_change_got_0"),
    (_change_diff(False, True) * 2, "expected_exactly_one_change_got_2"),
    ([{**_change_diff(False, True)[0], "object": "Pod/ns/other"}], "change_on_wrong_object"),
    (_change_diff(False, True, "spec.y"), "change_on_spec.y_expected_spec.x"),
    (_change_diff(False, 1), "change_is_not_False_to_True"),
    ([{"op": "add_field", "path": "spec.x", "new": True, "object": "Pod/ns/p"}], "change_on_spec.x_expected_spec.x"),
])
def test_expect_single_change_rejects_everything_else(diff, reason):
    assert expect_single_change(diff, KEY, "spec.x", False, True) == ("INVALID_PAIR", reason)


def test_per_candidate_pattern_drives_applicability_and_cases(catalog, seed):
    mr04 = catalog["MR-04"]
    ok, why = mr04.applicable(seed("rbac-basic"))
    assert (ok, why) == (False, "no_container_with_explicit_privileged_false")
    assert len(mr04.generate_parameters(seed("pod-basic"), 1)) == 1


def test_custom_relation_predicate_plugs_into_the_checker(monkeypatch):
    monkeypatch.setitem(checker.RELATIONS, "differ", lambda a, b: ("ok", "") if a != b else ("violation", "same"))
    from k8s_mr_lab.model import FAIL, PASS, NormalizedReport
    k = ("", "Pod", "ns", "p")
    r1, r2 = NormalizedReport("x"), NormalizedReport("x")
    r1.add("C-1", k, PASS)
    r2.add("C-1", k, FAIL)
    assert checker.check(SimpleNamespace(relation="differ", all_failures=False), [("C-1", k)], r1, r2).result == "PASS"
    r2.add("C-1", k, PASS)
    assert checker.check(SimpleNamespace(relation="differ", all_failures=False), [("C-1", k)], r1, r2).result == "VIOLATION"


# ------------------------------------------------------------------ MR-06: worked example of the new workflow
POD = """apiVersion: v1
kind: Pod
metadata: {name: web, namespace: lab-h}
spec:
  hostNetwork: false
  containers: [{name: c, image: nginx}]
---
apiVersion: v1
kind: Pod
metadata: {name: plain, namespace: lab-h}
spec:
  containers: [{name: c, image: nginx}]
"""


def pod_bundle(tmp_path, text=POD) -> ConfigBundle:
    from k8s_mr_lab.bundles import load_bundle
    f = tmp_path / "b.yaml"
    f.write_text(text, encoding="utf-8")
    return load_bundle(f, "hostnet")


def test_mr06_positive_deterministic_and_source_untouched(catalog, tmp_path):
    mr, src = catalog["MR-06"], pod_bundle(tmp_path)
    before = copy.deepcopy(src.objects)
    (p,) = mr.generate_parameters(src, 9)                      # 'plain' has no explicit hostNetwork: not a candidate
    assert p["workload"][3] == "web"
    fu, trace = mr.transform(src, p)
    assert fu.dump() == mr.transform(src, p)[0].dump() and src.objects == before
    d = diff_bundles(src, fu)
    assert len(d) == 1 and d[0]["path"] == "spec.hostNetwork" and (d[0]["old"], d[0]["new"]) == (False, True)
    assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "") and trace["workload"] == fmt_key(tuple(p["workload"]))
    assert mr.targets(src, p) == {"workload": [tuple(p["workload"])]}


def test_mr06_counterexamples(catalog, tmp_path):
    mr = catalog["MR-06"]
    assert mr.applicable(pod_bundle(tmp_path, POD.split("---")[1]))[0] is False        # no explicit hostNetwork
    src = pod_bundle(tmp_path)
    (p,) = mr.generate_parameters(src, 9)
    fu, _ = mr.transform(src, p)
    fu.objects[0]["spec"]["hostPID"] = True                                              # a second, unrelated change
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"


# ------------------------------------------------------------------ authoring CLI
def test_mr_validate_passes_on_the_repository(capsys):
    from k8s_mr_lab.cli import main
    assert main(["--config", str(ROOT / "config/scanners.yaml"), "--mapping", str(ROOT / "config/policy-mapping.yaml"),
                 "--catalog", str(CATALOG), "mr", "--properties", str(PROPS), "--patterns", str(PATS), "validate",
                 "--seeds", str(ROOT / "seeds/synthetic"), str(ROOT / "seeds/historical")]) == 0
    assert "0 error(s)" in capsys.readouterr().out


def test_exercise_catches_a_transform_that_mutates_the_source(catalog, seed, mapping):
    mr = catalog["MR-04"]
    orig = type(mr).transform

    def bad(self, source, params):
        source.objects[0]["metadata"]["labels"] = {"oops": "1"}                         # mutates the source
        return orig(self, source, params)
    type(mr).transform = bad
    try:
        errors, _, _ = mr_tools.exercise(mr, [ROOT / "seeds/synthetic/pod-basic"], mapping)
    finally:
        type(mr).transform = orig
    assert any("transform mutated the source" in e for e in errors)


def test_trace_matrix_lists_every_mr(mapping, tmp_path):
    out = tmp_path / "t.md"
    mr_tools.cmd_trace(SimpleNamespace(properties=str(PROPS), out=str(out)), str(CATALOG), mapping)
    text = out.read_text(encoding="utf-8")
    assert all(f"| MR-0{i} |" in text for i in range(1, 7)) and "K02" in text and "CWE-269" in text and "KSV-0009" in text and "(unverified)" not in text


def test_scaffold_writes_skeleton_and_refuses_to_overwrite(tmp_path, capsys):
    a = SimpleNamespace(id="MR-07", name="host-pid-flip", pattern="KP3", src_dir=str(tmp_path))
    assert mr_tools.cmd_scaffold(a) == 0
    code = (tmp_path / "host_pid_flip.py").read_text(encoding="utf-8")
    compile(code, "host_pid_flip.py", "exec")
    assert '@implements("MR-07")' in code and "class HostPidFlip(ControlledChange)" in code
    assert "id: MR-07" in capsys.readouterr().out
    assert mr_tools.cmd_scaffold(a) == 1


def test_mr06_candidate_seed_and_mapping(catalog, mapping):
    from k8s_mr_lab.bundles import load_bundle
    src = load_bundle(ROOT / "seeds" / "candidate" / "pod-hostnet", "pod-hostnet")
    assert catalog["MR-06"].applicable(src)[0]
    assert [(e.control, e.target) for e in mapping.entries("MR-06", "trivy")] == [("KSV-0009", "workload")]
    assert [(e.control, e.target) for e in mapping.entries("MR-06", "kubescape")] == [("C-0041", "workload")]
    assert "Pod" in mapping.control_kinds("trivy")["KSV-0009"] and "Pod" in mapping.control_kinds("kubescape")["C-0041"]


def test_no_property_reference_is_left_unverified():
    for p in mr_tools.load_properties(PROPS):
        for lst in mr_tools.REF_LISTS:
            assert all(r["verified"] for r in p.get(lst) or []), (p["id"], lst)
