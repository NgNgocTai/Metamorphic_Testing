"""Classify, case by case, what changed between archived runs made BEFORE the framework was unified and a run made AFTER.

    python scripts/migration_impact.py --scanner trivy --new runs/poc_v2/trivy --old runs/trivy --old <more old run dirs> \
        --old-mapping-rev HEAD --out docs/poc/migration_impact_trivy

Nothing is hidden: every case that is not UNCHANGED is listed with the reason. A change is EXPECTED only when it follows from a
documented difference between the old and the new mapping (a (control, target) pair removed or added for that MR and scanner);
anything else is UNEXPECTED_REGRESSION or UNRESOLVED and makes the exit code non-zero (BLOCKED).

Categories: UNCHANGED | EXPECTED_CHANGE | NEW_BEHAVIOR | BUG_FIX (only via --bug-fix <case_id>) | UNEXPECTED_REGRESSION | UNRESOLVED
The old runs are evidence archived for audit; this script only reads them.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

CATEGORIES = ("UNCHANGED", "EXPECTED_CHANGE", "NEW_BEHAVIOR", "BUG_FIX", "UNEXPECTED_REGRESSION", "UNRESOLVED")


def load_rows(run: Path) -> dict[str, dict]:
    return {r["case_id"]: r for r in json.loads((run / "results.json").read_text(encoding="utf-8"))}


def comps(row: dict) -> dict[tuple[str, str], tuple]:
    a = row.get("assessment") or {}
    return {(c["control"], c["resource"]): (c["source"], c["followup"], c["outcome"]) for c in a.get("comparisons") or []}


def old_mapping(rev: str, path: str) -> dict:
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, check=True).stdout
    return yaml.safe_load(out)


def pairs(mapping: dict, scanner: str) -> dict[str, dict[str, set[tuple[str, str]]]]:
    """mr -> {'p': {(control, target)}}; role is ignored for old mappings (it did not exist)."""
    out: dict[str, set[tuple[str, str]]] = {}
    for mr, per in (mapping.get("mrs") or {}).items():
        out[mr] = {(e["control"], e["target"]) for e in (per or {}).get(scanner) or []}
    return out


def kind(resource: str) -> str:
    return resource.split("/", 1)[0]


def classify(case_id: str, scanner: str, old: dict | None, new: dict | None, delta: dict, vocab: dict, bug_fix: set[str],
             remaining: dict, kinds_grown: dict, kinds_shrunk: dict) -> tuple[str, str]:
    mr_id = (new or old)["mr_id"]
    dropped = bool(delta.get(mr_id, (set(), set()))[0]) and not remaining.get(mr_id)     # the whole (MR, scanner) scope left the mapping
    if old is None and dropped and new["mr_result"] == "SKIP" and new.get("skip_reason") == "mr_not_mapped_for_scanner":
        return "EXPECTED_CHANGE", "one SKIP row (mr_not_mapped_for_scanner) now stands for the cases of an MR whose Trivy/Kubescape scope was removed from the mapping"
    if new is None and dropped:
        return "EXPECTED_CHANGE", "case no longer generated: the (MR, scanner) scope was removed from the mapping (declared under unsupported)"
    if old is None:
        return "NEW_BEHAVIOR", "case did not exist in the archived runs (new MR, seed or parameter)"
    if new is None:
        return "UNRESOLVED", "case existed before and is absent from the new run"
    mr = new["mr_id"]
    removed_pairs, added_pairs = delta.get(mr, (set(), set()))
    oc, nc = comps(old), comps(new)
    flips = [k for k in oc.keys() & nc.keys() if oc[k][:2] != nc[k][:2]]
    gone = [k for k in oc.keys() - nc.keys()]
    came = [k for k in nc.keys() - oc.keys()]
    explained_gone = [k for k in gone if any(c == k[0] and kind(k[1]) in vocab.get(t, []) for c, t in removed_pairs) or kind(k[1]) in kinds_shrunk.get(k[0], ())]
    explained_came = [k for k in came if any(c == k[0] and kind(k[1]) in vocab.get(t, []) for c, t in added_pairs) or kind(k[1]) in kinds_grown.get(k[0], ())]
    same_result = old["mr_result"] == new["mr_result"]
    if same_result and not flips and not gone and not came:
        return ("BUG_FIX", "listed with --bug-fix") if case_id in bug_fix else ("UNCHANGED", "")
    if flips:
        return "UNEXPECTED_REGRESSION", f"{len(flips)} verdict(s) differ for a key present in both runs, e.g. {flips[0]}: {oc[flips[0]][:2]} -> {nc[flips[0]][:2]}"
    if len(explained_gone) != len(gone) or len(explained_came) != len(came):
        left = [k for k in gone if k not in explained_gone] + [k for k in came if k not in explained_came]
        return "UNRESOLVED", f"{len(left)} comparison key(s) changed without a mapping change that explains them, e.g. {left[0]}"
    if not same_result:
        if new["mr_result"] == "SKIP" and removed_pairs and not nc:
            return "EXPECTED_CHANGE", f"{old['mr_result']} -> SKIP: scope for {mr}/{scanner} removed from the mapping ({new.get('skip_reason') or new.get('reason')})"
        if (old["mr_result"], new["mr_result"]) in {("PASS", "VIOLATION")} and explained_came:
            viol = [k for k in explained_came if nc[k][2] == "violation"]
            if viol:
                return "EXPECTED_CHANGE", f"PASS -> VIOLATION driven only by keys added by the scope extension, e.g. {viol[0]}"
        return "UNRESOLVED", f"result {old['mr_result']} -> {new['mr_result']} not explained by the scope change"
    return "EXPECTED_CHANGE", f"{len(explained_gone)} key(s) dropped and {len(explained_came)} key(s) added by the documented scope or registry change; result unchanged"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--old", action="append", required=True)
    ap.add_argument("--old-mapping-rev", default="HEAD")
    ap.add_argument("--old-mapping-path", default="k8s-mr-lab/config/policy-mapping.yaml")
    ap.add_argument("--mapping", default="config/policy-mapping.yaml")
    ap.add_argument("--registry", default="config/control-registry.yaml")
    ap.add_argument("--bug-fix", action="append", default=[])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    new_map = yaml.safe_load(Path(a.mapping).read_text(encoding="utf-8"))
    old_map = old_mapping(a.old_mapping_rev, a.old_mapping_path)
    po, pn = pairs(old_map, a.scanner), pairs(new_map, a.scanner)
    delta = {mr: (po.get(mr, set()) - pn.get(mr, set()), pn.get(mr, set()) - po.get(mr, set())) for mr in set(po) | set(pn)}
    vocab = {t: d["kinds"] for t, d in (new_map.get("targets") or {}).items()}
    vocab["bound_role"] = vocab.get("bound_role", ["Role", "ClusterRole"])
    old_kinds = {c: set(m.get("kinds") or []) for c, m in ((old_map.get("controls") or {}).get(a.scanner) or {}).items()}
    reg = yaml.safe_load(Path(a.registry).read_text(encoding="utf-8"))["controls"][a.scanner]
    new_kinds = {c: set(m["reports_on"]) for c, m in reg.items()}
    grown = {c: new_kinds[c] - old_kinds.get(c, set()) for c in new_kinds}     # kinds a control now reports on (registry) that the old `kinds` omitted
    shrunk = {c: old_kinds[c] - new_kinds.get(c, set()) for c in old_kinds}
    old_rows: dict[str, dict] = {}
    for d in a.old:
        for cid, r in load_rows(Path(d)).items():
            old_rows.setdefault(cid, r)
    new_rows = load_rows(Path(a.new))
    scored = []
    for cid in sorted(set(old_rows) | set(new_rows)):
        o, n = old_rows.get(cid), new_rows.get(cid)
        if o is not None and o["mr_id"] == "*":
            continue
        cat, why = classify(cid, a.scanner, o, n, delta, vocab, set(a.bug_fix), pn, grown, shrunk)
        scored.append({"case_id": cid, "mr_id": (n or o)["mr_id"], "old": o["mr_result"] if o else None, "new": n["mr_result"] if n else None,
                       "category": cat, "reason": why})
    by = Counter((s["mr_id"], s["category"]) for s in scored)
    summary = {"scanner": a.scanner, "old_runs": a.old, "new_run": a.new, "old_mapping_rev": a.old_mapping_rev,
               "totals": dict(Counter(s["category"] for s in scored)), "by_mr": {f"{m}/{c}": n for (m, c), n in sorted(by.items())},
               "cases": scored, "blocked": any(s["category"] in ("UNEXPECTED_REGRESSION", "UNRESOLVED") for s in scored)}
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = [f"# Migration impact: {a.scanner}", "", f"old runs: {', '.join(a.old)}; new run: `{a.new}`; old mapping from git `{a.old_mapping_rev}`", "",
             "| category | cases |", "|---|---|"] + [f"| {c} | {summary['totals'].get(c, 0)} |" for c in CATEGORIES]
    lines += ["", "## Every case that is not UNCHANGED", "", "| case | MR | old | new | category | reason |", "|---|---|---|---|---|---|"]
    lines += [f"| `{s['case_id']}` | {s['mr_id']} | {s['old']} | {s['new']} | {s['category']} | {s['reason']} |" for s in scored if s["category"] != "UNCHANGED"]
    lines += ["", f"**BLOCKED**: {summary['blocked']}"]
    out.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"totals": summary["totals"], "blocked": summary["blocked"]}))
    return 1 if summary["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
