"""CLI: generate | run | triage | report | versions | mr (list|validate|trace|scaffold)."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import mr_tools, seeds as seedlib
from . import report as rep
from .bundles import BundleError, load_bundle
from .experiment import EXPERIMENT_TYPES, provenance
from .registry import PolicyMapping, UnknownMRError, active_mrs, load_catalog
from .runner import Runner
from .scanners import SCANNERS, load_scanner_config, make_scanner
from .triage import load_known_issues, triage_run
from .validation import diff_bundles, unified_text_diff, validate_source

ROOT = Path.cwd()


def _paths(a) -> tuple[dict, PolicyMapping, dict]:
    cfg = load_scanner_config(a.config)
    return cfg, PolicyMapping.load(a.mapping), load_catalog(a.catalog)


def seed_dirs(roots: list[str]) -> list[Path]:
    out: list[Path] = []
    for r in roots:
        p = Path(r)
        if any(p.glob("*.yaml")) or any(p.glob("*.yml")):
            out.append(p)
        else:
            out += sorted(d for d in p.iterdir() if d.is_dir() and (any(d.glob("*.yaml")) or any(d.glob("*.yml"))))
    return out


def cmd_generate(a) -> int:
    _, mapping, catalog = _paths(a)
    out = Path(a.out)
    n_pairs = n_valid = 0
    for sd in seed_dirs(a.seeds):
        try:
            src = load_bundle(sd, sd.name)
        except BundleError as e:
            print(f"{sd.name}: INVALID_SOURCE {e}")
            continue
        if validate_source(src):
            print(f"{sd.name}: INVALID_SOURCE {validate_source(src)}")
            continue
        for mr in active_mrs(catalog, a.mr):
            ok, why = mr.applicable(src)
            if not ok:
                print(f"{mr.id:6} {sd.name:22} SKIP  {why}")
                continue
            for params in mr.generate_parameters(src, a.max_cases):
                fu, trace = mr.transform(src, params)
                status, reason = mr.validate_pair(src, fu, params)
                cid = f"{mr.id}__{sd.name}__{rep_digest(params)}"
                d = out / cid
                src.write(d / "source")
                fu.write(d / "followup")
                (d / "diff.patch").write_text(unified_text_diff(src, fu), encoding="utf-8")
                (d / "diff.json").write_text(json.dumps(diff_bundles(src, fu), indent=2, default=str), encoding="utf-8")
                (d / "trace.json").write_text(json.dumps({"mr": mr.id, "params": params, "pair_status": status, **trace}, indent=2), encoding="utf-8")
                n_pairs += 1
                n_valid += status == "VALID_PAIR"
                print(f"{mr.id:6} {sd.name:22} {status:12} {cid}")
    print(f"\ngenerated {n_pairs} follow-ups, {n_valid} structurally valid -> {out}")
    return 0


def rep_digest(params: dict) -> str:
    from .runner import digest
    return digest(params)


def cmd_run(a) -> int:
    cfg, mapping, catalog = _paths(a)
    scanner = make_scanner(a.scanner, cfg)
    runner = Runner(scanner, mapping, catalog, Path(a.out), use_cache=not a.no_cache)
    results = []
    for sd in seed_dirs(a.seeds):
        res = runner.run_seed(sd, a.mr, a.max_cases)
        results += res
        for r in res:
            print(f"{r.mr_id:6} {r.seed_id:22} {r.result:14} {r.case_id.rsplit('__', 1)[-1]:>10}  {r.reason[:90]}")
    lock = runner.environment_lock()
    lock["total_scanner_invocations"] = runner.total_invocations
    lock["experiment"] = provenance(experiment_type=a.experiment_type, experiment_id=a.experiment_id, scope_profile=a.scope_profile,
                                   catalog_path=a.catalog, mapping_path=a.mapping, seed_dirs=seed_dirs(a.seeds), runner=runner, mr_ids=a.mr)
    rep.write_run(Path(a.out), runner.run_id, results, catalog, lock)
    counts = {}
    for r in results:
        counts[r.result] = counts.get(r.result, 0) + 1
    print(f"\n{a.scanner} {lock['scanner_version']} [{lock['scan_mode']}]: {counts}; scanner invocations: {runner.total_invocations}; -> {a.out}")
    return 1 if (a.fail_on_violation and counts.get("VIOLATION")) else 0


def cmd_triage(a) -> int:
    cfg, mapping, catalog = _paths(a)
    run_dir = Path(a.run)
    lock = json.loads((run_dir / "environment.lock.json").read_text(encoding="utf-8"))
    scanner = make_scanner(lock["scanner"], cfg)
    runner = Runner(scanner, mapping, catalog, run_dir / "triage-work", use_cache=False)
    t = triage_run(run_dir, runner, cfg, load_known_issues(Path(a.known_issues)), minimize=a.minimize)
    for cid, c in t["cases"].items():
        print(f"{cid}\n   {c['status']}  family={c['family']}  known={c['known_issue'] or '-'}")
    print(f"\n{len(t['cases'])} alert(s) triaged (candidates only) -> {run_dir / 'triage.json'}")
    return 0


def cmd_report(a) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    summaries, triages, all_rows = [], {}, []
    for rd in map(Path, a.runs):
        rows, lock = rep.load_run(rd)
        tri = json.loads((rd / "triage.json").read_text(encoding="utf-8")) if (rd / "triage.json").exists() else None
        summaries.append(rep.summarize(rows, lock, tri))
        if tri:
            triages[lock["scanner"]] = tri
        all_rows += rows
    (out / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    (out / "REPORT.md").write_text(rep.markdown_report(summaries, triages), encoding="utf-8")
    with open(out / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, rep.RESULT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(all_rows)
    print((out / "REPORT.md").read_text(encoding="utf-8"))
    return 0


def cmd_mr(a) -> int:
    if a.mr_cmd == "scaffold":
        return mr_tools.cmd_scaffold(a, a.catalog)
    mapping = PolicyMapping.load(a.mapping)
    if a.mr_cmd == "list":
        return mr_tools.cmd_list(load_catalog(a.catalog), mapping)
    if a.mr_cmd == "validate":
        return mr_tools.cmd_validate(a, a.catalog, mapping)
    if a.mr_cmd == "requirements":
        return mr_tools.cmd_requirements(a, a.catalog, mapping)
    if a.mr_cmd == "review-packet":
        return mr_tools.cmd_review_packet(a, load_catalog(a.catalog), mapping)
    if a.mr_cmd == "informative":
        return mr_tools.cmd_informative(a, mapping)
    if a.mr_cmd == "patterns":
        return mr_tools.cmd_patterns(a, a.catalog)
    if a.mr_cmd == "explain":
        return mr_tools.cmd_explain(a, load_catalog(a.catalog), mapping)
    return mr_tools.cmd_trace(a, a.catalog, mapping)


def cmd_seeds(a) -> int:
    """seeds inventory | coverage | select | split: deterministic, no scanner."""
    parts = dict(p.split("=", 1) for p in (a.partition or []))
    recs = seedlib.inventory(a.roots, parts)
    if a.seeds_cmd == "inventory":
        print(f"{'seed':<46} {'valid':<6} {'objs':>4} {'tokens':>6}  partition / duplicate")
        for r in recs:
            print(f"{r.root + '/' + r.seed_id:<46} {str(r.valid):<6} {r.n_objects:>4} {len(r.tokens):>6}  {r.partition}{' dup-of ' + r.duplicate_of if r.duplicate_of else ''}"
                  f"{'  ' + r.problems[0][:50] if r.problems else ''}")
        if a.out:
            Path(a.out).write_text(json.dumps([r.to_json() for r in recs], indent=1), encoding="utf-8")
        return 0
    if a.seeds_cmd == "coverage":
        cov = seedlib.coverage(recs)
        print(f"seeds {cov['seeds']}")
        for d, v in cov["dimensions"].items():
            print(f"  {d:<16} {v['covered']}/{v['defined']}  missing: {', '.join(v['missing']) or '-'}")
        print(f"tokens covered {cov['covered_tokens']}/{cov['defined_tokens']}")
        res = {"coverage": cov}
        if a.with_mr:
            app = seedlib.mr_applicability(recs, load_catalog(a.catalog))
            res["mr_applicability"] = app
            for k, v in app.items():
                print(f"  {k}: applicable on {v['applicable_seeds']}/{v['usable_seeds']} usable seeds, {v['cases']} case(s)")
        if a.out:
            Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
        return 0
    if a.seeds_cmd == "select":
        for r in seedlib.select(recs, a.k):
            print(f"{r.root}/{r.seed_id}")
        return 0
    sp = seedlib.split(recs, a.evaluation_percent)
    for k, v in sp.items():
        print(f"{k}	{v}")
    if a.out:
        Path(a.out).write_text(json.dumps({"salt": "k8s-mr-lab-split-v1", "evaluation_percent": a.evaluation_percent, "split": sp}, indent=1), encoding="utf-8")
    return 0


def cmd_versions(a) -> int:
    cfg = load_scanner_config(a.config)
    bad = 0
    for name in SCANNERS:
        sc = make_scanner(name, cfg)
        v, pin = sc.version(), str(cfg[name].get("version"))
        ok = v == pin
        bad += not ok
        print(f"{name:10} found={v:12} pinned={pin:10} mode={sc.mode:11} policy={sc.policy_digest()[:16]} {'OK' if ok else 'MISMATCH'}")
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):          # reports contain non-ASCII text; never die on a cp1252 console
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="k8s-mr-lab", description=__doc__)
    p.add_argument("--config", default="config/scanners.yaml")
    p.add_argument("--mapping", default="config/policy-mapping.yaml")
    p.add_argument("--catalog", default="mrs/catalog.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write source/follow-up pairs without scanning")
    g.add_argument("--seeds", nargs="+", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--mr", action="append")
    g.add_argument("--max-cases", type=int, default=4)
    g.set_defaults(fn=cmd_generate)

    r = sub.add_parser("run", help="run MR pairs through a real scanner")
    r.add_argument("--scanner", choices=sorted(SCANNERS), required=True)
    r.add_argument("--seeds", nargs="+", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--mr", action="append")
    r.add_argument("--max-cases", type=int, default=4)
    r.add_argument("--no-cache", action="store_true")
    r.add_argument("--fail-on-violation", action="store_true")
    r.add_argument("--experiment-type", choices=EXPERIMENT_TYPES, default="baseline")
    r.add_argument("--experiment-id", help="stable id of this experiment (default: the run id)")
    r.add_argument("--scope-profile", default="official", help="label of the comparison scope used (the shipped mapping is `official`)")
    r.set_defaults(fn=cmd_run)

    t = sub.add_parser("triage", help="reproduce violations and write reproducer packages (candidates only)")
    t.add_argument("--run", required=True)
    t.add_argument("--known-issues", default="docs/known_issues.yaml")
    t.add_argument("--minimize", action="store_true")
    t.set_defaults(fn=cmd_triage)

    s = sub.add_parser("report", help="aggregate run directories")
    s.add_argument("--runs", nargs="+", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_report)

    v = sub.add_parser("versions", help="check installed scanner versions against the pins")
    v.set_defaults(fn=cmd_versions)

    m = sub.add_parser("mr", help="author and check MRs: list | validate | trace | scaffold")
    m.add_argument("--properties", default="mrs/security_properties.yaml")
    m.add_argument("--patterns", default="mrs/patterns.yaml")
    m.add_argument("--requirements", default="mrs/requirements.yaml")
    msub = m.add_subparsers(dest="mr_cmd", required=True)
    msub.add_parser("list", help="catalog overview")
    mv = msub.add_parser("validate", help="STRUCTURAL gate: schema, traceability, MR contract on valid seeds (no scanner; not a semantic proof)")
    mv.add_argument("--seeds", nargs="+", default=["seeds/synthetic", "seeds/historical", "seeds/candidate"])
    mt = msub.add_parser("trace", help="Property -> Pattern -> MR -> control traceability matrix")
    mt.add_argument("--out")
    msub.add_parser("requirements", help="requirement -> MR matrix with coverage X/N (checked against the catalog)")
    mr_ = msub.add_parser("review-packet", help="write a packet for an INDEPENDENT reviewer (decision left blank, status PENDING)")
    mr_.add_argument("id")
    mr_.add_argument("--out")
    mi = msub.add_parser("informative", help="classify the comparisons of saved runs: could the control observe the change? (reporting only)")
    mi.add_argument("--run", nargs="+", required=True, help="run directories with cases/ (or packaged evidence directories)")
    mi.add_argument("--out")
    mp = msub.add_parser("patterns", help="MR x template-element matrix and the grouping it implies (MST-wi Table 4 method)")
    mp.add_argument("--out")
    me = msub.add_parser("explain", help="explain one MR from its metadata; with --case, explain a saved case from its evidence")
    me.add_argument("id")
    me.add_argument("--case", help="a saved case directory (runs/<scanner>/cases/<case_id> or a packaged evidence case)")
    ms = msub.add_parser("scaffold", help="write an MR implementation skeleton and print the catalog stub")
    ms.add_argument("id")
    ms.add_argument("name", help="kebab-case name, e.g. host-network-flip")
    ms.add_argument("--pattern", default="KP3")
    ms.add_argument("--src-dir", default="src/k8s_mr_lab/transforms")
    m.set_defaults(fn=cmd_mr)

    sd = sub.add_parser("seeds", help="seed inventory / coverage / deterministic selection / dev-eval split (no scanner)")
    sd.add_argument("seeds_cmd", choices=["inventory", "coverage", "select", "split"])
    sd.add_argument("--roots", nargs="+", required=True, help="directories of seed directories, or of flat YAML files")
    sd.add_argument("--partition", nargs="*", help="ROOTNAME=DEV|REGRESSION|EXTERNAL ...; DEV/REGRESSION are always development")
    sd.add_argument("--k", type=int, default=10)
    sd.add_argument("--evaluation-percent", type=int, default=30)
    sd.add_argument("--with-mr", action="store_true", help="coverage: also count MR applicability (static)")
    sd.add_argument("--out")
    sd.set_defaults(fn=cmd_seeds)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except UnknownMRError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
