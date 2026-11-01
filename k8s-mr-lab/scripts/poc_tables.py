"""Generate the result tables of docs/poc/POC_RESULTS.md from run directories. Nothing here is typed by hand.

    python scripts/poc_tables.py --trivy runs/final/trivy --kubescape runs/final/kubescape \
        --kd-affected runs/final/kd001/v4.0.11 --kd-fixed runs/final/kd001/v4.0.12 --kd-old-affected docs/evidence/poc_final/kd001-old-scope/v4.0.11 --kd-old-fixed docs/evidence/poc_final/kd001-old-scope/v4.0.12 \
        --mutant runs/final/mr09-mutant --out out/poc_tables.md

Each table states what it counts. `results.csv` verdict columns are filled only for VIOLATION rows, so everything is read from
`comparisons.csv` and `results.json`.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

AGGREGATOR = ("C-0015", "C-0007", "C-0035", "C-0053")


def rows(run: Path) -> list[dict]:
    return json.loads((run / "results.json").read_text(encoding="utf-8"))


def comps(run: Path) -> list[dict]:
    with open(run / "comparisons.csv", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def lock(run: Path) -> dict:
    return json.loads((run / "environment.lock.json").read_text(encoding="utf-8"))


def md(header: list[str], body: list[list]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(str(x) for x in r) + " |" for r in body]


def environment(run: Path) -> list[str]:
    lk, ex = lock(run), lock(run).get("experiment", {})
    return [f"- scanner `{lk['scanner']} {lk['scanner_version']}` ({lk['scan_mode']}), policy digest `{str(lk['policy_digest'])[:16]}`, "
            f"experiment `{ex.get('experiment_id')}` ({ex.get('experiment_type')}), scope `{ex.get('scope_profile')}`, "
            f"registry_matches_policy `{ex.get('registry_matches_policy')}`, framework `{(ex.get('framework_git') or {}).get('commit', '')[:10]}` "
            f"(dirty `{(ex.get('framework_git') or {}).get('dirty')}`), mapping+registry `{ex.get('digests', {}).get('mapping_and_registry')}`, "
            f"seed digest `{str(ex.get('seed_digest'))[:12]}`"]


def per_mr(run: Path) -> list[str]:
    rs, cs = rows(run), comps(run)
    res: dict[str, Counter] = defaultdict(Counter)
    for r in rs:
        res[r["mr_id"]][r["mr_result"]] += 1
    tier: dict[str, Counter] = defaultdict(Counter)
    for c in cs:
        tier[c["mr_id"]][c["tier"]] += 1
    statuses = ("PASS", "PARTIAL", "VIOLATION", "SKIP", "INVALID_SOURCE", "INCONCLUSIVE", "INVALID_PAIR", "SCAN_ERROR", "ENVIRONMENT_MISMATCH")
    head = ["MR", *statuses, "comparisons", "INFORMATIVE", "WEAK", "CONTROL", "UNINFORMATIVE", "INCONCLUSIVE"]
    body = []
    for mr in sorted(res):
        t = tier.get(mr, Counter())
        body.append([mr, *(res[mr].get(s, 0) for s in statuses), sum(t.values()), *(t.get(k, 0) for k in
                     ("INFORMATIVE", "WEAK", "CONTROL", "UNINFORMATIVE", "INCONCLUSIVE"))])
    return md(head, body)


def violations(run: Path) -> list[str]:
    body = [[c["case_id"], c["control"], c["resource"], c["role"], f"{c['source_verdict']} -> {c['followup_verdict']}", c["basis"], c["tier"]]
            for c in comps(run) if c["outcome"] == "violation"]
    return md(["case", "control", "resource", "role", "verdict", "basis", "tier"], body) if body else ["_no violation_"]


def aggregator_keys(run: Path) -> dict[tuple[str, str, str], dict]:
    out = {}
    for c in comps(run):
        if c["control"] in AGGREGATOR and c["mr_id"] == "MR-02":
            out[(c["case_id"], c["control"], c["resource"])] = c
    return out


def kd001(affected: Path, fixed: Path, label: str) -> list[str]:
    """Four verdicts per key: (affected | fixed) x (source | follow-up), on keys present in both runs."""
    a, f = aggregator_keys(affected), aggregator_keys(fixed)
    both = sorted(set(a) & set(f))
    cnt = Counter((a[k]["source_verdict"], a[k]["followup_verdict"], f[k]["source_verdict"], f[k]["followup_verdict"]) for k in both)
    body = [[*k, n] for k, n in sorted(cnt.items())]
    differing = [k for k in both if (a[k]["source_verdict"], a[k]["followup_verdict"]) != (f[k]["source_verdict"], f[k]["followup_verdict"])]
    src_equal = all(a[k]["source_verdict"] == f[k]["source_verdict"] for k in both)
    cases = sorted({k[0] for k in differing})
    ctl = Counter(k[1] for k in differing)
    kinds = Counter(k[2].split("/", 1)[0] for k in differing)
    out = [f"**{label}** keys compared in both runs: {len(both)}; keys whose verdicts differ between binaries: {len(differing)} "
           f"(cases {len(cases)}; controls {dict(ctl)}; kinds {dict(kinds)}); source verdicts identical on all keys: {src_equal}", ""]
    out += md(["affected source", "affected follow-up", "fixed source", "fixed follow-up", "keys"], body)
    viol = lambda run: len({c["case_id"] for c in comps(run) if c["outcome"] == "violation"})
    out += ["", f"MR-02 cases with a VIOLATION: affected {viol(affected)}, fixed {viol(fixed)}"]
    return out


def kd001_cases(affected: Path, fixed: Path) -> list[str]:
    """Per case: the MR assessment on both binaries and, for every aggregator key whose verdicts differ, the four verdicts."""
    ar = {r["case_id"]: r["mr_result"] for r in rows(affected)}
    fr = {r["case_id"]: r["mr_result"] for r in rows(fixed)}
    a, f = aggregator_keys(affected), aggregator_keys(fixed)
    body = []
    for cid in sorted(c for c in ar if c in fr and ar[c] != "SKIP"):
        diff = [k for k in sorted(set(a) & set(f)) if k[0] == cid and (a[k]["source_verdict"], a[k]["followup_verdict"]) != (f[k]["source_verdict"], f[k]["followup_verdict"])]
        shown = "; ".join(f"{k[1]} {k[2].split('@')[0]}: aff {a[k]['source_verdict']}->{a[k]['followup_verdict']} / fix {f[k]['source_verdict']}->{f[k]['followup_verdict']}" for k in diff[:4])
        body.append([f"`{cid}`", ar[cid], fr[cid], len(diff), shown or "-"])
    return md(["case", "MR-02 on affected v4.0.11", "MR-02 on fixed v4.0.12", "aggregator keys that differ", "four verdicts (first 4)"], body)


def scope_compare(old: Path, new: Path, label: str) -> list[str]:
    """What a change of comparison scope did to the comparisons of the same cases: nothing conclusive may be lost or flipped."""
    o = {(r["case_id"], r["control"], r["resource"]): r for r in comps(old)}
    n = {(r["case_id"], r["control"], r["resource"]): r for r in comps(new)}
    concl = lambda r: r["source_verdict"] in ("PASS", "FAIL") and r["followup_verdict"] in ("PASS", "FAIL")
    lost = [k for k, r in o.items() if concl(r) and k not in n]
    dropped = Counter(k[1] + " on " + k[2].split("/", 1)[0] for k, r in o.items() if not concl(r) and k not in n)
    flips = [k for k in o if k in n and (o[k]["source_verdict"], o[k]["followup_verdict"]) != (n[k]["source_verdict"], n[k]["followup_verdict"])]
    added = [k for k in n if k not in o]
    out = [f"**{label}**: comparisons before {len(o)}, after {len(n)}; conclusive comparisons lost {len(lost)}; verdict flips on common keys {len(flips)}; "
           f"new keys {len(added)}; inconclusive (no verdict on both sides) keys removed from scope {sum(dropped.values())}", ""]
    return out + (md(["removed key (control on kind)", "count"], [[k, v] for k, v in dropped.most_common(10)]) if dropped else [])


def mutation(pinned: Path, mutant: Path, mr: str) -> list[str]:
    pc = {(c["case_id"], c["control"], c["resource"]): c for c in comps(pinned) if c["mr_id"] == mr}
    mc = {(c["case_id"], c["control"], c["resource"]): c for c in comps(mutant) if c["mr_id"] == mr}
    keys = sorted(set(pc) & set(mc))
    diff = [k for k in keys if (pc[k]["source_verdict"], pc[k]["followup_verdict"]) != (mc[k]["source_verdict"], mc[k]["followup_verdict"])]
    body = [[k[0], k[1], k[2], f"{pc[k]['source_verdict']} -> {pc[k]['followup_verdict']} ({pc[k]['outcome']})",
             f"{mc[k]['source_verdict']} -> {mc[k]['followup_verdict']} ({mc[k]['outcome']})"] for k in diff]
    rs = lambda run: Counter(r["mr_result"] for r in rows(run) if r["mr_id"] == mr)
    out = [f"{mr} results pinned: {dict(rs(pinned))}; mutant: {dict(rs(mutant))}; keys compared in both: {len(keys)}; keys with different verdicts: {len(diff)}", ""]
    return out + (md(["case", "control", "resource", "pinned", "mutant"], body) if body else ["_the mutant is not distinguishable from the pinned policy on these keys_"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--kubescape", required=True)
    ap.add_argument("--kd-affected")
    ap.add_argument("--kd-fixed")
    ap.add_argument("--kd-old-affected")
    ap.add_argument("--kd-old-fixed")
    ap.add_argument("--mutant")
    ap.add_argument("--mutant-mr", default="MR-09")
    ap.add_argument("--scope-compare", nargs=3, metavar=("OLD_HELDOUT_KUBESCAPE", "NEW_HELDOUT_KUBESCAPE", "LABEL"))
    ap.add_argument("--heldout-trivy")
    ap.add_argument("--heldout-kubescape")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    L: list[str] = ["<!-- generated by scripts/poc_tables.py from the run directories named below; do not edit by hand -->", ""]
    for name, d in (("Trivy", a.trivy), ("Kubescape", a.kubescape)):
        L += [f"## {name}: all MRs, one pipeline", ""] + environment(Path(d)) + ["", f"Run directory: `{d}`", ""] + per_mr(Path(d))
        L += ["", f"Violations ({name}):", ""] + violations(Path(d)) + [""]
    if a.kd_affected and a.kd_fixed:
        L += ["## MR-02 historical defect (KD-001): affected v4.0.11 vs fixed v4.0.12", ""]
        L += environment(Path(a.kd_affected)) + environment(Path(a.kd_fixed)) + [""]
        L += kd001(Path(a.kd_affected), Path(a.kd_fixed), "official scope (unified)") + [""]
        L += ["Per case:", ""] + kd001_cases(Path(a.kd_affected), Path(a.kd_fixed)) + [""]
        if a.kd_old_affected and a.kd_old_fixed:
            L += ["Old scope (aggregator controls on the bound Role only), archived evidence:", ""]
            def viol(run):                       # archived runs have results.csv only
                with open(Path(run) / "results.csv", encoding="utf-8", newline="") as f:
                    return sorted({r["case_id"] for r in csv.DictReader(f) if r["mr_result"] == "VIOLATION"})
            L += [f"- affected: {len(viol(a.kd_old_affected))} VIOLATION case(s); fixed: {len(viol(a.kd_old_fixed))}; "
                  f"cases violating only under the affected binary: {len(set(viol(a.kd_old_affected)) - set(viol(a.kd_old_fixed)))}", ""]
    if a.mutant:
        L += [f"## {a.mutant_mr} mutation (C-0015 without the `watch` verb) vs the pinned policy", ""]
        L += environment(Path(a.mutant)) + [""] + mutation(Path(a.kubescape), Path(a.mutant), a.mutant_mr) + [""]
    for name, d in (("Trivy", a.heldout_trivy), ("Kubescape", a.heldout_kubescape)):
        if d:
            L += [f"## Independent seeds (Kalm-Benchmark, catalog frozen first): {name}", ""] + environment(Path(d)) + [""] + per_mr(Path(d)) + [""]
            L += [f"Violations ({name}, independent seeds):", ""] + violations(Path(d)) + [""]
    if a.scope_compare:
        L += ["## Effect of the control-scope rule on the independent seeds (before vs after, Kubescape)", ""] + scope_compare(Path(a.scope_compare[0]), Path(a.scope_compare[1]), a.scope_compare[2]) + [""]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"-> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
