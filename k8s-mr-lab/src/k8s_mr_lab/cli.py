"""CLI: generate | run | triage | report | versions."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import report as rep
from .bundles import BundleError, load_bundle
from .registry import PolicyMapping, load_catalog
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
        for mr in catalog.values():
            if a.mr and mr.id not in a.mr:
                continue
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

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
