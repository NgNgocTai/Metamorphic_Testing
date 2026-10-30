"""Result serialization and aggregation (JSON, CSV, Markdown). Denominators are always stated explicitly."""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from .model import R_PASS, R_SKIP, R_VIOLATION, VALID_PAIR, fmt_key
from .runner import CaseResult

RESULT_COLUMNS = [
    "run_id", "case_id", "seed_id", "mr_id", "params_digest", "scanner", "scanner_version", "scan_mode", "policy_digest",
    "target_control", "target_resource", "precondition_status", "pair_status", "source_verdict", "followup_verdict",
    "mr_relation", "mr_result", "skip_reason", "inconclusive_reason", "scanner_invocations", "elapsed_ms",
    "triage_status", "defect_family", "issue_url", "source_artifact", "followup_artifact", "raw_output_paths",
    "gen_ms", "scan_ms", "cache_hits", "source_sha256", "followup_sha256"]
COMPARISON_COLUMNS = ["run_id", "case_id", "mr_id", "scanner", "control", "resource", "source_verdict",
                      "followup_verdict", "outcome", "reason"]


def case_row(run_id: str, cr: CaseResult, relation: str) -> dict:
    a = cr.assessment
    viol = [k for k in a.key_results if k.outcome == "violation"] if a else []
    first = viol[0] if viol else None
    inv = cr.source_inv
    skipped = cr.result == R_SKIP
    return {
        "run_id": run_id, "case_id": cr.case_id, "seed_id": cr.seed_id, "mr_id": cr.mr_id,
        "params_digest": cr.case_id.rsplit("__", 1)[-1], "scanner": cr.scanner,
        "scanner_version": inv.version if inv else "", "scan_mode": inv.mode if inv else "",
        "policy_digest": inv.policy_digest[:16] if inv else "",
        "target_control": ";".join(sorted({k.control for k in a.key_results})) if a else "",
        "target_resource": ";".join(sorted({fmt_key(k.resource) for k in (viol or (a.key_results if a else []))})),
        "precondition_status": "NOT_MET" if skipped and cr.pair_status == "" else "MET",
        "pair_status": cr.pair_status, "source_verdict": first.source if first else "",
        "followup_verdict": first.followup if first else "", "mr_relation": relation, "mr_result": cr.result,
        "skip_reason": cr.reason if skipped else "",
        "inconclusive_reason": cr.reason if cr.result not in (R_PASS, R_VIOLATION, R_SKIP) else "",
        "scanner_invocations": cr.invocations, "elapsed_ms": cr.elapsed_ms, "triage_status": "", "defect_family": "",
        "issue_url": "", "source_artifact": f"{cr.case_dir}/source/bundle.yaml" if cr.case_dir else "",
        "followup_artifact": f"{cr.case_dir}/followup/bundle.yaml" if cr.case_dir else "",
        "raw_output_paths": f"{cr.case_dir}/scanner-source.json|{cr.case_dir}/scanner-followup.json" if inv else "",
        "gen_ms": cr.gen_ms, "scan_ms": cr.scan_ms, "cache_hits": cr.cache_hits,
        "source_sha256": cr.source_sha, "followup_sha256": cr.followup_sha}


def write_run(out_dir: Path, run_id: str, results: list[CaseResult], catalog: dict, lock: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [case_row(run_id, r, catalog[r.mr_id].relation if r.mr_id in catalog else "") for r in results]
    with open(out_dir / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, RESULT_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(out_dir / "comparisons.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, COMPARISON_COLUMNS)
        w.writeheader()
        for r in results:
            for k in (r.assessment.key_results if r.assessment else []):
                w.writerow({"run_id": run_id, "case_id": r.case_id, "mr_id": r.mr_id, "scanner": r.scanner,
                            "control": k.control, "resource": fmt_key(k.resource), "source_verdict": k.source,
                            "followup_verdict": k.followup, "outcome": k.outcome, "reason": k.reason})
    (out_dir / "results.json").write_text(json.dumps([
        {**row, "params": r.params, "assessment": r.assessment.to_json() if r.assessment else None, "reason": r.reason}
        for row, r in zip(rows, results)], indent=2, default=str), encoding="utf-8")
    (out_dir / "environment.lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")


def load_run(run_dir: Path) -> tuple[list[dict], dict]:
    return (json.loads((run_dir / "results.json").read_text(encoding="utf-8")),
            json.loads((run_dir / "environment.lock.json").read_text(encoding="utf-8")))


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} = {100 * n / d:.0f}%" if d else "n/a (0 denominator)"


def summarize(rows: list[dict], lock: dict, triage: dict | None = None) -> dict:
    """Every ratio carries its numerator and denominator; nothing is reported without the unit it is counted in."""
    by_result = Counter(r["mr_result"] for r in rows)
    pairs = [r for r in rows if r["pair_status"]]                        # follow-ups actually generated
    valid = [r for r in pairs if r["pair_status"] == VALID_PAIR]
    scanned = [r for r in valid if r["mr_result"] not in (R_SKIP,)]      # reached the scanners
    conclusive = [r for r in scanned if r["mr_result"] in (R_PASS, R_VIOLATION)]
    sm = defaultdict(set)
    elig = defaultdict(set)
    for r in rows:
        sm[r["mr_id"]].add(r["seed_id"])
        if r["pair_status"]:
            elig[r["mr_id"]].add(r["seed_id"])
    considered = sum(len(v) for k, v in sm.items() if k != "*")
    eligible = sum(len(v) for v in elig.values())
    per_mr = {}
    for mr in sorted(sm):
        c = Counter(r["mr_result"] for r in rows if r["mr_id"] == mr)
        per_mr[mr] = dict(c)
    invocations = sum(int(r["scanner_invocations"] or 0) for r in rows)
    viol = [r for r in rows if r["mr_result"] == R_VIOLATION]
    families = sorted({t["family"] for t in (triage or {}).get("cases", {}).values()}) if triage else []
    return {
        "analysis": analysis(rows, triage),
        "scanner": lock.get("scanner"), "scanner_version": lock.get("scanner_version"), "scan_mode": lock.get("scan_mode"),
        "policy_digest": lock.get("policy_digest"), "run_id": lock.get("run_id"),
        "counts_by_result": dict(by_result), "counts_by_mr": per_mr,
        "metrics": {
            "applicability_rate (eligible (seed,MR) / considered (seed,MR))": _pct(eligible, considered),
            "valid_pair_rate (valid pairs / generated follow-ups)": _pct(len(valid), len(pairs)),
            "conclusive_comparison_rate (PASS+VIOLATION / pairs that reached the scanner)": _pct(len(conclusive), len(scanned)),
            "scanner_invocations (executed, source scans cached)": invocations,
            "alerts (VIOLATION cases)": len(viol),
            "provisional_defect_families (needs human confirmation)": families,
            "alert_precision_adjudicated": "n/a - no human adjudication recorded yet; unresolved alerts are not counted",
            "specificity": "not measured - no independently labelled negative cases",
        },
    }


def analysis(rows: list[dict], triage: dict | None = None) -> dict:
    """Deduplicated counts (RQ2) and cost (RQ3). Raw row counts stay in `counts_by_result` for traceability."""
    from statistics import median
    seeds = {r["seed_id"] for r in rows}
    invalid_seeds = {r["seed_id"] for r in rows if r["mr_result"] == "INVALID_SOURCE"}
    pairs = [r for r in rows if r["pair_status"]]
    scanned = [r for r in pairs if r["pair_status"] == VALID_PAIR and r["mr_result"] != R_SKIP]
    key = lambda r: (r["source_sha256"], r["followup_sha256"])
    viol = [r for r in rows if r["mr_result"] == R_VIOLATION]
    dup_groups: dict[str, list[str]] = defaultdict(list)       # identical scanned source text -> seeds
    for r in pairs:
        if r["seed_id"] not in dup_groups[r["source_sha256"]]:
            dup_groups[r["source_sha256"]].append(r["seed_id"])
    n = lambda k: sum(int(r.get(k) or 0) for r in scanned)
    per_mr: dict[str, dict] = {}
    for mr in sorted({r["mr_id"] for r in scanned}):
        rs = [r for r in scanned if r["mr_id"] == mr]
        per_mr[mr] = {"cases": len(rs), "median_gen_ms": median(int(r["gen_ms"]) for r in rs),
                      "median_scan_ms_per_case(cache hits count 0)": median(int(r["scan_ms"]) for r in rs),
                      "scanner_invocations": sum(int(r["scanner_invocations"]) for r in rs)}
    reasons = Counter(r["inconclusive_reason"] for r in rows if r["mr_result"] == "INCONCLUSIVE")
    skips = Counter(r["skip_reason"] for r in rows if r["mr_result"] == R_SKIP)
    fam = {c["family"] for c in (triage or {}).get("cases", {}).values()}
    return {
        "dedup": {
            "seed_configurations (all dirs, incl. invalid)": len(seeds), "invalid_sources": len(invalid_seeds),
            "unique_valid_source_texts": len({r["source_sha256"] for r in pairs}),
            "seeds_with_identical_source": [v for v in dup_groups.values() if len(v) > 1],
            "followups_generated": len(pairs), "unique_followup_texts": len({r["followup_sha256"] for r in pairs}),
            "pairs_scanned (rows)": len(scanned), "unique_pairs_scanned": len({key(r) for r in scanned}),
            "mr_violations (rows)": len(viol), "unique_pairs_with_violation": len({key(r) for r in viol}),
            "defect_candidate_families (provisional)": len(fam), "confirmed_defects": 0,
        },
        "rows_not_executed": {"SKIP": dict(skips), "INVALID_SOURCE": len(invalid_seeds)},
        "inconclusive_reasons": dict(reasons),
        "efficiency": {
            "sum_generation_ms": n("gen_ms"), "sum_scanner_ms (executed scans only)": n("scan_ms"),
            "sum_case_wall_ms": n("elapsed_ms"), "scanner_invocations_executed": n("scanner_invocations"),
            "scans_saved_by_cache": n("cache_hits"),
            "median_case_ms": median(int(r["elapsed_ms"]) for r in scanned) if scanned else None,
            "per_mr": per_mr,
            "manual_triage_load": {"alerts": len(viol), "unique_inputs": len({key(r) for r in viol}), "families": len(fam)},
        },
    }


def markdown_report(summaries: list[dict], triage_by_scanner: dict[str, dict]) -> str:
    L = ["# k8s-mr-lab - run report", "",
         "> Numbers below come from the real scanner binaries listed in each section. `VIOLATION` = an MR relation was",
         "> broken (an *alert*); it is not a confirmed defect until a human adjudicates it (see triage).", ""]
    for s in summaries:
        L += [f"## {s['scanner']} {s['scanner_version']} ({s['scan_mode']})", "",
              f"- policy digest: `{str(s['policy_digest'])[:16]}`  run: `{s['run_id']}`",
              f"- results: {s['counts_by_result']}", ""]
        for k, v in s["metrics"].items():
            L.append(f"- **{k}**: {v}")
        L += ["", "| MR | results |", "|---|---|"] + [f"| {m} | {c} |" for m, c in s["counts_by_mr"].items()] + [""]
        a = s.get("analysis")
        if a:
            L += ["### Deduplicated counts (RQ2)", ""] + [f"- {k}: {v}" for k, v in a["dedup"].items()]
            L += [f"- rows not executed: {a['rows_not_executed']}", f"- inconclusive reasons: {a['inconclusive_reasons']}", "",
                  "### Cost (RQ3)", ""]
            e = a["efficiency"]
            L += [f"- {k}: {v}" for k, v in e.items() if k != "per_mr"]
            L += ["", "| MR | cases | median gen ms | median scan ms/case | invocations |", "|---|---|---|---|---|"]
            L += [f"| {m} | {v['cases']} | {v['median_gen_ms']} | {v['median_scan_ms_per_case(cache hits count 0)']} | {v['scanner_invocations']} |"
                  for m, v in e["per_mr"].items()] + [""]
        t = triage_by_scanner.get(s["scanner"])
        if t and t.get("cases"):
            L += ["### Alerts after automatic triage", "",
                  "| case | family (provisional) | reproduced | known issue | note |", "|---|---|---|---|---|"]
            for cid, c in t["cases"].items():
                ki = f"{c['known_issue']} ({c['known_issue_match']})" if c.get("known_issue") else "-"
                L.append(f"| `{cid}` | {c['family']} | {c['reproduced']} | {ki} | {c['status']} |")
            L.append("")
    return "\n".join(L)
