"""Seed inventory, coverage, selection and split: deterministic, vocabulary fixed in advance, invalid and duplicate seeds never counted."""
from __future__ import annotations

import json
import shutil

from conftest import ROOT
from k8s_mr_lab import seeds as sd

ROOTS = [str(ROOT / "seeds" / "synthetic"), str(ROOT / "seeds" / "historical"), str(ROOT / "seeds" / "candidate")]
PARTS = {"synthetic": "DEV", "historical": "REGRESSION", "candidate": "DEV"}


def by_id(recs):
    return {r.seed_id: r for r in recs}


def test_vocabulary_is_fixed_and_has_52_tokens():
    assert len(sd.ALL_TOKENS) == 52 and len(set(sd.ALL_TOKENS)) == 52


def test_project_inventory_counts_invalid_and_duplicate_seeds_honestly():
    recs = sd.inventory(ROOTS, PARTS)
    r = by_id(recs)
    assert len(recs) == 8 and not r["invalid-missing-role"].valid
    assert r["K1-role-namespace"].duplicate_of == "synthetic/rbac-workload"          # same objects, different file
    assert len(sd.usable(recs)) == 6
    cov = sd.coverage(recs)
    assert cov["seeds"] == {"total": 8, "valid": 7, "duplicates": 1, "usable": 6, "invalid_or_unloadable": 1}
    assert (cov["covered_tokens"], cov["defined_tokens"]) == (17, 52)                 # the documented seed gap; update with the report


def test_feature_tokens_reflect_the_object_graph_not_just_kinds():
    r = by_id(sd.inventory(ROOTS, PARTS))
    assert "link:complete_chain" in r["rbac-workload"].tokens and "link:complete_chain" in r["rbac-secrets-reader"].tokens
    assert "link:complete_chain" not in r["pod-basic"].tokens and "link:complete_chain" not in r["rbac-basic"].tokens   # a SA+Role+binding without a workload is not a chain
    assert {"rule_resource:secrets", "rule_verb:watch", "security_context:privileged_false"} <= set(r["rbac-secrets-reader"].tokens)
    assert "security_context:host_network_false" in r["pod-hostnet"].tokens


def test_gaps_the_mutation_experiment_pointed_at_are_visible_in_coverage():
    missing = sd.coverage(sd.inventory(ROOTS, PARTS))["dimensions"]
    assert "cross_namespace_subject" in missing["link"]["missing"] and "multi_namespace" in missing["link"]["missing"]
    assert set(missing["subject_kind"]["missing"]) == {"User", "Group"}


def test_selection_is_deterministic_and_stops_when_nothing_new_is_covered():
    recs = sd.inventory(ROOTS, PARTS)
    a = [f"{x.root}/{x.seed_id}" for x in sd.select(recs, 10)]
    assert a == [f"{x.root}/{x.seed_id}" for x in sd.select(list(reversed(recs)), 10)]       # input order does not matter
    assert a[0] == "synthetic/rbac-secrets-reader" and len(a) < 6                              # largest first; redundant seeds not picked
    assert "historical/K1-role-namespace" not in a and "synthetic/invalid-missing-role" not in a


def test_split_is_reproducible_and_keeps_design_seeds_in_development():
    recs = sd.inventory(ROOTS, PARTS)
    assert set(sd.split(recs).values()) == {"development"}                                    # every project seed shaped an MR
    ext = sd.inventory(ROOTS, {"synthetic": "EXTERNAL", "historical": "EXTERNAL", "candidate": "EXTERNAL"})
    s1, s2 = sd.split(ext, 50), sd.split(list(reversed(ext)), 50)
    assert s1 == s2 and set(s1.values()) == {"development", "evaluation"}
    assert sd.split(ext, 0) and set(sd.split(ext, 0).values()) == {"development"}


def test_flat_directory_of_manifests_works_like_an_external_corpus(tmp_path):
    flat = tmp_path / "corpus"
    flat.mkdir()
    shutil.copy(ROOT / "seeds/synthetic/pod-basic/bundle.yaml", flat / "a.yaml")
    shutil.copy(ROOT / "seeds/synthetic/pod-basic/bundle.yaml", flat / "b.yaml")           # duplicate content
    (flat / "bad.yaml").write_text("a: 1\na: 2\n", encoding="utf-8")                        # duplicate key ⇒ unloadable
    (flat / "_skip.yaml").write_text("kind: Pod\n", encoding="utf-8")
    recs = sd.inventory([str(flat)], {"corpus": "EXTERNAL"})
    assert [r.seed_id for r in recs] == ["a", "b", "bad"]
    assert recs[1].duplicate_of == "corpus/a" and not recs[2].valid and recs[2].problems[0].startswith("load_error")
    assert [r.seed_id for r in sd.usable(recs)] == ["a"]


def test_mr_applicability_counts_cases_without_a_scanner(catalog):
    app = sd.mr_applicability(sd.inventory(ROOTS, PARTS), catalog)
    assert app["MR-02"]["applicable_seeds"] == 3 and app["MR-05"]["applicable_seeds"] == 1 and app["MR-07"]["applicable_seeds"] == 3
    assert all(v["usable_seeds"] == 6 for v in app.values())


def test_saved_coverage_evidence_matches_the_code():
    saved = json.loads((ROOT / "docs/evidence/seed_coverage_2026-11-01/project_seeds.json").read_text(encoding="utf-8"))
    assert saved["coverage"]["covered_tokens"] == 17 and saved["mr_applicability"]["MR-02"]["applicable_seeds"] == 3
