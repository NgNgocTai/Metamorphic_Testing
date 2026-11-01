"""MR construction framework: spec schema, traceability, patterns, MR-06 (worked example), authoring CLI."""
from __future__ import annotations

import copy
import re
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


def test_unsupported_scanner_control_mapping_is_rejected(mapping):
    data = copy.deepcopy(mapping.data)
    data["mrs"]["MR-04"]["trivy"].append({"control": "KSV-9999", "target": "workload", "reason": "x"})
    data["mrs"]["MR-77"] = {"trivy": []}
    problems = trace_problems(read_specs(CATALOG), mapping=PolicyMapping(data, mapping.registry))
    assert any("MR-04/trivy/KSV-9999->workload: control is not in control-registry.yaml" in p for p in problems)
    assert any("mapping lists unknown MR MR-77" in p for p in problems)


def test_candidate_is_skipped_unless_named(catalog):
    assert [m.id for m in active_mrs(catalog)] == ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05"]
    assert [m.id for m in active_mrs(catalog, ["MR-06"])] == ["MR-06"]
    assert [m.id for m in active_mrs(catalog, ["MR-07"])] == ["MR-07"]
    assert not {"MR-08", "MR-09"} & {m.id for m in active_mrs(catalog)}


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
    assert all(f"| MR-0{i} |" in text for i in range(1, 10)) and "K02" in text and "CWE-269" in text and "KSV-0009" in text and "(unverified)" not in text


def test_scaffold_refuses_to_overwrite(tmp_path):
    a = SimpleNamespace(id="MR-10", name="host-pid-flip", pattern="KP3", src_dir=str(tmp_path), patterns=str(PATS))
    assert mr_tools.cmd_scaffold(a, str(CATALOG)) == 0
    assert mr_tools.cmd_scaffold(a, str(CATALOG)) == 1


# ------------------------------------------------------------------ review findings (2026-11-01)
def test_unknown_mr_id_fails_fast(catalog, capsys):
    from k8s_mr_lab.cli import main
    from k8s_mr_lab.registry import UnknownMRError
    with pytest.raises(UnknownMRError, match=r"MR-99"):
        active_mrs(catalog, ["MR-06", "MR-99"])
    base = ["--config", str(ROOT / "config/scanners.yaml"), "--mapping", str(ROOT / "config/policy-mapping.yaml"),
            "--catalog", str(CATALOG)]
    assert main(base + ["generate", "--seeds", str(ROOT / "seeds/candidate"), "--mr", "MR-99", "--out", "unused"]) == 2
    assert "MR-99" in capsys.readouterr().err
    assert main(base + ["run", "--scanner", "trivy", "--seeds", str(ROOT / "seeds/candidate"), "--mr", "MR-99",
                        "--out", "unused"]) == 2


@pytest.mark.parametrize("field,value,msg", [
    ("preconditions", "just a string", "non-empty list"),
    ("limits", [], "non-empty list"),
    ("pair_checks", ["ok", ""], "non-empty list"),
    ("scope", "", "non-empty string"),
    ("property_id", None, "non-empty string"),
    ("all_failures", "yes", "boolean"),
    ("id", "MR_1", "must look like MR-01"),
])
def test_spec_type_validation(tmp_path, field, value, msg):
    specs = specs_copy()
    specs[0][field] = value
    with pytest.raises(ValueError, match=msg):
        read_specs(write_catalog(tmp_path, specs))


def test_pattern_requires_matching_base_class(mapping):
    specs = specs_copy()
    specs[0]["pattern"], specs[0]["relation"] = "KP3", "pass_to_fail"      # MR-01 is not a ControlledChange
    props = copy.deepcopy(mr_tools.load_properties(PROPS))
    props[0]["candidate_patterns"].append("KP3")
    problems = trace_problems(specs, props=props, mapping=mapping)
    assert any("MR-01: pattern KP3 requires base class ControlledChange" in p for p in problems)


def test_mapping_entry_must_have_control_target_and_reason(mapping):
    data = copy.deepcopy(mapping.data)
    data["mrs"]["MR-04"]["trivy"].append({"control": "KSV-0017"})
    data["mrs"]["MR-04"]["kubescape"].append({"control": "", "target": "workload", "reason": "x"})
    problems = trace_problems(read_specs(CATALOG), mapping=PolicyMapping(data, mapping.registry))
    assert sum("needs non-empty control, target and reason" in p for p in problems) == 2


def test_exercise_skips_invalid_sources(catalog, mapping):
    mr = catalog["MR-01"]
    valid = ROOT / "seeds/synthetic/pod-basic"
    invalid = ROOT / "seeds/synthetic/invalid-missing-role"
    n_valid = mr_tools.exercise(mr, [valid], mapping)[2]
    assert n_valid > 0
    assert mr_tools.exercise(mr, [valid, invalid], mapping)[2] == n_valid       # the invalid seed adds no exercised case
    assert mr_tools.exercise(mr, [invalid], mapping)[2] == 0


def _scaffold(tmp_path, **kw):
    a = SimpleNamespace(**{"id": "MR-10", "name": "x-flip", "pattern": "KP3", "src_dir": str(tmp_path),
                           "patterns": str(PATS), **kw})
    return mr_tools.cmd_scaffold(a, str(CATALOG))


def test_scaffold_is_pattern_aware(tmp_path):
    assert _scaffold(tmp_path, name="kp3-mr", pattern="KP3") == 0
    kp3 = (tmp_path / "kp3_mr.py").read_text(encoding="utf-8")
    assert "class Kp3Mr(ControlledChange)" in kp3 and "expected_change" in kp3
    assert _scaffold(tmp_path, name="kp1-mr", pattern="KP1") == 0
    kp1 = (tmp_path / "kp1_mr.py").read_text(encoding="utf-8")
    assert "class Kp1Mr(MetamorphicRelation)" in kp1 and "ControlledChange" not in kp1 and "validate_pair" in kp1
    for code in (kp3, kp1):
        compile(code, "x.py", "exec")


@pytest.mark.parametrize("kw", [{"pattern": "KP9"}, {"id": "MR-01"}, {"id": "mr7"}])
def test_scaffold_refuses_bad_input_and_writes_nothing(tmp_path, kw):
    assert _scaffold(tmp_path, **kw) == 2
    assert list(tmp_path.iterdir()) == []


def test_compare_runs_rejects_duplicates_and_count_mismatch(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("compare_runs", ROOT / "scripts" / "compare_runs.py")
    cr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cr)
    head_r = ",".join(("case_id", "target_control", "target_resource") + cr.RESULTS_VALUES)
    head_c = ",".join(("case_id", "control", "resource") + cr.COMPARISON_VALUES)
    row_r = "c1,KSV-1,Pod/p,PASS,,,VALID_PAIR,,,s,f"
    row_c = "c1,KSV-1,Pod/p,PASS,FAIL,ok,"

    def run(name, results, comps):
        d = tmp_path / name
        d.mkdir()
        (d / "results.csv").write_text(head_r + "\n" + "\n".join(results) + "\n", encoding="utf-8")
        (d / "comparisons.csv").write_text(head_c + "\n" + "\n".join(comps) + "\n", encoding="utf-8")
        return d
    a = run("a", [row_r], [row_c])
    assert cr.main(str(a), str(run("same", [row_r], [row_c]))) == 0
    assert cr.main(str(a), str(run("dup", [row_r, row_r], [row_c]))) == 1                 # duplicate key
    assert cr.main(str(a), str(run("dupc", [row_r], [row_c, row_c]))) == 1
    assert cr.main(str(a), str(run("verdict", [row_r], ["c1,KSV-1,Pod/p,PASS,PASS,ok,"]))) == 1   # differs only in comparisons.csv
    assert cr.main(str(a), str(run("missing", [row_r], []))) == 1


# ------------------------------------------------------------------ template elements, mr patterns, mr explain
def test_template_is_required_and_typed(tmp_path):
    specs = specs_copy()
    del specs[0]["template"]
    with pytest.raises(ValueError, match="missing required field.*template"):
        read_specs(write_catalog(tmp_path, specs))
    specs = specs_copy()
    specs[0]["template"] = {"preconditions": [], "followup": []}
    with pytest.raises(ValueError, match="field 'template'"):
        read_specs(write_catalog(tmp_path, specs))


def test_template_elements_are_checked_against_the_vocabulary():
    elements = mr_tools.load_template_elements(PATS)
    assert mr_tools.check_template(read_specs(CATALOG), elements) == []
    specs = specs_copy()
    specs[1]["template"]["followup"] = ["G-TELEPORT"]
    specs[3]["template"]["preconditions"] = ["P-VERDICT"]          # derived, must not be declared
    bad = mr_tools.check_template(specs, elements)
    assert any("MR-02: unknown template followup element G-TELEPORT" in b for b in bad)
    assert any("MR-04: template element P-VERDICT is derived" in b for b in bad)


def test_template_row_derives_verdict_scope_and_output():
    rows = {s["id"]: mr_tools.template_row(s) for s in read_specs(CATALOG)}
    assert rows["MR-01"] == {"G-REWRITE", "S-ALL", "O-EQUAL"}
    assert rows["MR-04"] == {"P-STRUCT", "P-VERDICT", "G-MODIFY", "S-TARGET", "O-PASS-TO-FAIL"}
    assert "P-VERDICT" not in rows["MR-02"] and "O-FAIL-TO-PASS" in rows["MR-05"]


def test_element_groups_follow_the_mstwi_rule():
    _, rows = mr_tools.element_matrix(read_specs(CATALOG), mr_tools.load_template_elements(PATS))
    groups = mr_tools.element_groups(rows)
    assert groups[0] == ["MR-04", "MR-06"]                          # the only identical combination today
    assert sorted(map(tuple, groups[1:])) == [("MR-01",), ("MR-02",), ("MR-03",), ("MR-05",), ("MR-07",), ("MR-08",), ("MR-09",)]


def test_mr_patterns_reports_coarser_families(capsys):
    mr_tools.cmd_patterns(SimpleNamespace(patterns=str(PATS), out=None), str(CATALOG))
    out = capsys.readouterr().out
    assert "KP2 = MR-02: spans EP3 -> identical" in out and "KP4 = MR-09" in out
    assert "KP3 = MR-04, MR-05, MR-06" in out and "coarser than the element level" in out


EVIDENCE = ROOT / "docs" / "evidence" / "p0_reverification_2026-11-01"


def _explain(capsys, mr_id, case=None):
    from k8s_mr_lab.cli import main
    args = ["--config", str(ROOT / "config/scanners.yaml"), "--mapping", str(ROOT / "config/policy-mapping.yaml"),
            "--catalog", str(CATALOG), "mr", "--properties", str(PROPS), "--patterns", str(PATS), "explain", mr_id]
    rc = main(args + (["--case", str(case)] if case else []))
    return rc, capsys.readouterr()


@pytest.mark.parametrize("mr_id", ["MR-01", "MR-02", "MR-03", "MR-04", "MR-05", "MR-06", "MR-07", "MR-08", "MR-09"])
def test_explain_works_for_every_catalog_mr(capsys, mr_id):
    rc, out = _explain(capsys, mr_id)
    assert rc == 0
    for field in ("Security property", "MR pattern", "Relation", "Preconditions", "Transformation", "Implementation",
                  "Known limitations"):
        assert field in out.out


def test_explain_a_real_violation_case_with_triage(capsys):
    case = EVIDENCE / "kubescape" / "cases" / "MR-02__rbac-workload__66de14dad8"
    rc, out = _explain(capsys, "MR-02", case)
    assert rc == 0
    assert "VIOLATION" in out.out and "C-0267" in out.out and "PASS -> FAIL  violation  [explicit]" in out.out
    assert "add_object Role/lab-a-decoy/app-role" in out.out
    assert "CANDIDATE_REPRODUCED" in out.out and "kubescape/issues/2579" in out.out


def test_explain_reports_missing_evidence_as_not_available(capsys, tmp_path):
    d = tmp_path / "MR-02__x__0"
    d.mkdir()
    rc, out = _explain(capsys, "MR-02", d)
    assert rc == 0
    assert out.out.count("NOT_AVAILABLE") >= 5 and "PASS ->" not in out.out


def test_explain_rejects_a_case_of_another_mr_and_unknown_ids(capsys):
    case = EVIDENCE / "trivy" / "cases" / "MR-05__rbac-secrets-reader__d31cd60ffd"
    rc, out = _explain(capsys, "MR-02", case)
    assert rc == 2 and "is a case of MR-05" in out.out
    rc, out = _explain(capsys, "MR-42")
    assert rc == 2 and "MR-42" in out.err



# ------------------------------------------------------------------ documentation must not point at things that do not exist
def test_docs_reference_existing_files_and_cli_commands():
    import re
    from k8s_mr_lab.cli import main
    docs = ROOT / "docs"
    text = "\n".join(p.read_text(encoding="utf-8") for p in [ROOT / "README.md", *docs.glob("*.md"), *docs.glob("case_studies/*.md")])
    missing = sorted({m for m in re.findall(r"`(docs/[A-Za-z0-9_./-]+\.(?:md|json|csv))`", text)
                      if not (ROOT / m).exists() and "<" not in m and "*" not in m})
    assert missing == [], missing
    for cmd in ("list", "validate", "trace", "patterns", "explain", "scaffold"):
        assert f"mr {cmd}" in text, cmd
    with pytest.raises(SystemExit):
        main(["mr", "no-such-subcommand"])



def test_unverified_references_carry_a_basis_and_cis_is_not_called_verified(mapping):
    props = copy.deepcopy(mr_tools.load_properties(PROPS))
    for p in props:
        for lst in mr_tools.REF_LISTS:
            for ref in p.get(lst) or []:
                assert isinstance(ref["verified"], bool), (p["id"], lst)
                if not ref["verified"]:
                    assert ref.get("basis"), (p["id"], lst, ref)
        assert not any(r["verified"] for r in p.get("cis_nsa") or []), p["id"]   # the CIS document itself was not consulted
    hostns = next(p for p in props if p["id"] == "SP-POD-HOST-NAMESPACES")
    assert "not consulted" in hostns["cis_nsa"][0]["basis"]
    # the tool enforces it: an unverified reference without a basis is a traceability problem
    del hostns["cis_nsa"][0]["basis"]
    assert any("unverified cis_nsa entry must say why" in b for b in trace_problems(read_specs(CATALOG), props=props, mapping=mapping))


# ------------------------------------------------------------------ evidence sanitiser
def test_sanitize_evidence_keeps_a_trace_to_the_originals(tmp_path):
    import hashlib
    import importlib.util
    import json
    spec = importlib.util.spec_from_file_location("sanitize_evidence", ROOT / "scripts" / "sanitize_evidence.py")
    se = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(se)
    src = tmp_path / "ev"
    (src / "case").mkdir(parents=True)
    raw = '{"controlsInputs": "/home/alice/.kubescape/x.json", "win": "D:\\Code\\KLTN\\Tools\\a", "ok": "/home/USER/y"}'
    (src / "case" / "a.json").write_text(raw, encoding="utf-8")
    (src / "case" / "plain.txt").write_text("nothing personal here", encoding="utf-8")
    (src / "blob.bin").write_bytes(b"\x00/home/alice\xff")
    out = tmp_path / "pub"
    rec = se.sanitize_tree(src, out)
    pub = json.loads((out / "case" / "a.json").read_text(encoding="utf-8"))
    assert pub["controlsInputs"] == "/home/USER/.kubescape/x.json" and pub["win"] == "<WINDOWS_PROJECT_PATH>" and pub["ok"] == "/home/USER/y"
    assert (out / "blob.bin").read_bytes() == b"\x00/home/alice\xff"                    # non-text files are copied byte for byte
    f = rec["files"]
    assert f["case/a.json"]["original_sha256"] == hashlib.sha256(raw.encode()).hexdigest() != f["case/a.json"]["sanitized_sha256"]
    assert f["case/plain.txt"]["original_sha256"] == f["case/plain.txt"]["sanitized_sha256"]
    assert se.scan(out) == [] and se.scan(src) != []
    assert (src / "case" / "a.json").read_text(encoding="utf-8") == raw                   # the original is untouched
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        se.sanitize_tree(src, out)


def test_review_packet_never_records_a_decision(capsys, tmp_path):
    from k8s_mr_lab.cli import main
    out = tmp_path / "MR-07.md"
    base = ["--config", str(ROOT / "config/scanners.yaml"), "--mapping", str(ROOT / "config/policy-mapping.yaml"), "--catalog", str(CATALOG)]
    assert main(base + ["mr", "--properties", str(PROPS), "--patterns", str(PATS), "review-packet", "MR-07", "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "PENDING_INDEPENDENT_REVIEW" in text and "author_reviewed" in text
    assert len([ln for ln in text.splitlines() if re.match(r"\| Q\d \|", ln)]) == 8 and "independently_reviewed" in text
    assert "| Người review | |" in text and "| Quyết định | ACCEPT / ACCEPT_WITH_CHANGES / REJECT |" in text     # blank form
    assert "ACCEPT" not in text.replace("ACCEPT / ACCEPT_WITH_CHANGES / REJECT", "").replace("chỉ** khi quyết định là ACCEPT", "")
    assert main(base + ["mr", "--properties", str(PROPS), "--patterns", str(PATS), "review-packet", "MR-42"]) == 2


def test_package_run_evidence_can_sanitise_before_hashing(tmp_path):
    import hashlib
    import importlib.util
    import json
    spec = importlib.util.spec_from_file_location("package_run_evidence", ROOT / "scripts" / "package_run_evidence.py")
    pk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pk)
    src = ROOT / "docs" / "evidence" / "mr07_dev_2026-11-01" / "kubescape"            # a packaged run that still carries /home/<user>
    out = tmp_path / "pub"
    assert pk.main([str(src), str(out), "--mr", "MR-07", "--sanitize"]) == 0
    man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert man["sanitized"] is True
    changed = {k: v for k, v in man["files"].items() if "original_sha256" in v}
    assert changed and all(v["original_sha256"] != v["sha256"] for v in changed.values())
    for rel, v in man["files"].items():                                                 # the manifest describes the files as shipped
        assert hashlib.sha256((out / rel).read_bytes()).hexdigest() == v["sha256"], rel
    se_spec = importlib.util.spec_from_file_location("sanitize_evidence", ROOT / "scripts" / "sanitize_evidence.py")
    se = importlib.util.module_from_spec(se_spec)
    se_spec.loader.exec_module(se)
    assert se.scan(out) == []
    for rel, v in changed.items():                                                      # and each changed file maps back to its original in the source package
        assert hashlib.sha256((src / rel).read_bytes()).hexdigest() == v["original_sha256"], rel
