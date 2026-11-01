"""Requirement -> MR matrix (mrs/requirements.yaml) and MR-09, the MR derived from requirement R08."""
from __future__ import annotations

import copy
import pathlib
from types import SimpleNamespace

from conftest import ROOT
from k8s_mr_lab import mr_tools
from k8s_mr_lab.model import VALID_PAIR
from k8s_mr_lab.registry import read_specs

REQS = ROOT / "mrs" / "requirements.yaml"
CATALOG = ROOT / "mrs" / "catalog.yaml"


def problems(data, mapping, specs=None):
    return mr_tools.check_requirements(data, specs if specs is not None else read_specs(CATALOG), mapping)


# ------------------------------------------------------------------ requirement matrix
def test_shipped_requirements_are_consistent_and_counted_honestly(mapping, capsys):
    data = mr_tools.load_requirements(REQS)
    specs = read_specs(CATALOG)
    assert problems(data, mapping) == []
    rs = {r["id"]: r for r in data["requirements"]}
    assert len(rs) == 10 and not {"status", "mr_ids", "origin"} & {k for r in rs.values() for k in r}      # the link lives in the catalog only
    links = mr_tools.requirement_links(specs)
    status = {i: mr_tools.requirement_status(links.get(i, []), rs[i].get("uncovered")) for i in rs}
    assert status["R08"] == "COVERED" and links["R08"] == [{"mr": "MR-09", "coverage": "full", "origin": "prospective"}]
    assert all(links[i][0]["origin"] == "retrospective" for i in ("R01", "R02"))       # labelling an old MR is not deriving it
    assert status["R02"] == "PARTIAL" and status["R03"] == "DERIVABLE_NOT_IMPLEMENTED"
    assert rs["R05"]["reason"] == "CONTRACT_NOT_READ" and rs["R09"]["reason"] == "RELATION_NOT_SUPPORTED"
    mr_tools.cmd_requirements(SimpleNamespace(requirements=str(REQS)), str(CATALOG), mapping)
    out = capsys.readouterr().out
    assert "with a full MR: 3/10" in out and "partial MR only: 1/10" in out
    assert "MRs NOT attached to any of these requirements" in out and "MR-01" in out


def test_requirements_without_a_real_mr_cannot_be_counted_as_covered(mapping):
    data = copy.deepcopy(mr_tools.load_requirements(REQS))
    specs = copy.deepcopy(read_specs(CATALOG))
    rs = {r["id"]: r for r in data["requirements"]}
    del rs["R03"]["uncovered"]                           # no MR and no declared reason for the gap
    specs[0]["requirements"] = [{"id": "R99", "coverage": "full"}]          # the catalog points at a requirement that does not exist
    rs["R05"]["reason"] = "BECAUSE"                      # undeclared reason code
    rs["R04"]["uncovered"] = "VALIDATED"                 # unknown status
    rs["R02"]["status"] = "HAS_MR"                       # a status stated here instead of derived from the catalog
    rs["R01"]["uncovered"] = "NOT_FEASIBLE"              # claims no coverage while MR-04 covers it
    rs["R06"]["quote"] = ""
    rs["R07"]["owasp"]["id"] = "K11"
    rs["R10"]["contract_read"] = ["KSV-9999"]
    bad = " | ".join(problems(data, mapping, specs))
    for expect in ("R03: no MR in the catalog, so it needs 'uncovered'", "catalog references unknown requirement R99",
                   "R05: NOT_FEASIBLE needs a reason", "R04: no MR in the catalog, so it needs 'uncovered'",
                   "R02: 'status' is derived from the catalog", "R01: has MR(s) ['MR-04'] so it must not declare",
                   "R06: missing quote", "R07: owasp id must be one of", "R10: contract_read must be a subset of controls"):
        assert expect in bad, expect


def test_catalog_origin_prospective_or_retrospective_needs_a_requirement():
    specs = copy.deepcopy(read_specs(CATALOG))
    specs[8]["requirements"] = []                        # MR-09 is prospective
    import tempfile
    import yaml
    import pytest
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "c.yaml"
        f.write_text(yaml.safe_dump({"mrs": specs}), encoding="utf-8")
        with pytest.raises(ValueError, match="MR-09: origin prospective needs at least one requirement"):
            read_specs(f)


def test_requirement_quotes_are_present_unabridged_and_from_official_docs():
    for r in mr_tools.load_requirements(REQS)["requirements"]:
        assert r["quote"].strip() == r["quote"] and "..." not in r["quote"], r["id"]
        assert r["source"]["url"].startswith("https://kubernetes.io/docs/"), r["id"]


# ------------------------------------------------------------------ MR-09
def _mr09(catalog, seed):
    mr, src = catalog["MR-09"], seed("rbac-secrets-reader")
    return mr, src, mr.generate_parameters(src, 9)


def test_mr09_one_case_per_other_read_verb_and_only_the_verbs_change(catalog, seed):
    mr, src, params = _mr09(catalog, seed)
    assert [p["to_verbs"] for p in params] == [["get"], ["list"], ["watch"]]       # the source rule names get, list, watch
    before = copy.deepcopy(src.objects)
    for p in params:
        fu, _ = mr.transform(src, p)
        assert mr.validate_pair(src, fu, p) == (VALID_PAIR, "")
        rule = fu.find("Role", "lab-c", "reader-role")["rules"][0]
        assert rule["verbs"] == p["to_verbs"] and rule["resources"] == ["secrets"] and rule["apiGroups"] == [""]
    assert src.objects == before and mr.transform(src, params[0])[0].dump() == mr.transform(src, params[0])[0].dump()
    role = ("rbac.authorization.k8s.io", "Role", "lab-c", "reader-role")
    assert mr.targets(src, params[0]) == {"role_direct": [role], "bound_role": [role]}


def test_mr09_counterexamples_are_not_eligible(catalog, seed):
    mr = catalog["MR-09"]
    reason = "no_role_with_a_core_secrets_rule_using_only_get_list_watch"
    for mutate in (lambda r: r.update(resourceNames=["only-this"]),               # list/watch differ from get with resourceNames
                   lambda r: r.update(resources=["secrets", "configmaps"]),       # several resources
                   lambda r: r.update(apiGroups=["apps"]),                        # not the core group
                   lambda r: r.update(verbs=["get", "create"]),                   # a verb outside the read set
                   lambda r: r.update(verbs=["*"])):
        src = seed("rbac-secrets-reader")
        mutate(src.find("Role", "lab-c", "reader-role")["rules"][0])
        assert mr.applicable(src) == (False, reason)
    src = seed("rbac-secrets-reader")                                              # a second rule also reaches Secrets
    src.find("Role", "lab-c", "reader-role")["rules"].append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["delete"]})
    assert not mr.applicable(src)[0]
    assert not mr.applicable(seed("rbac-workload"))[0]


def test_mr09_invalid_pairs_are_rejected(catalog, seed):
    mr, src, params = _mr09(catalog, seed)
    p = params[0]
    fu, _ = mr.transform(src, p)
    fu.find("Role", "lab-c", "reader-role")["rules"][0]["resources"] = ["secrets", "pods"]   # unrelated extra change
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"
    fu, _ = mr.transform(src, p)
    fu.find("Role", "lab-c", "reader-role")["rules"][0]["verbs"] = ["get", "delete"]         # leaves the equivalence set
    assert mr.validate_pair(src, fu, p)[0] == "INVALID_PAIR"
    assert mr.validate_pair(src, src.clone(), p) == ("INVALID_PAIR", "not_exactly_the_requested_verb_substitution")


def test_mr09_mapping_matches_what_the_pinned_contracts_cover(mapping):
    assert [(e.control, e.target) for e in mapping.entries("MR-09", "trivy")] == [("KSV-0113", "role_direct")]
    assert [(e.control, e.target) for e in mapping.entries("MR-09", "kubescape")] == [("C-0015", "bound_role")]
    assert mapping.control_kinds("trivy")["KSV-0113"] == ["Role"]
