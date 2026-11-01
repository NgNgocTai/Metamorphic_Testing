"""Triage: turn MR violations into reproducible *candidates*. It never declares a defect CONFIRMED - that needs a human."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path

import yaml

from .bundles import load_bundle, obj_key
from .model import R_VIOLATION, fmt_key
from .runner import Runner
from .scanners.base import expand


def load_known_issues(path: Path) -> list[dict]:
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("issues", []) if path.exists() else []


def _lines(text: str, pattern: str, limit: int = 8) -> list[str]:
    rx = re.compile(pattern)
    return [f"{i}: {ln.strip()}" for i, ln in enumerate(text.splitlines(), 1) if rx.search(ln)][:limit]


def rule_evidence(scanner: str, control: str, mr, mapping, cfg: dict) -> dict:
    """Static rule-source evidence for a violating control (aid for the human adjudicator, not an oracle)."""
    key, pattern = mr.rule_probe or ("", "")
    if scanner == "trivy":
        rego = mapping.control_meta("trivy", control).get("source")
        base = expand(cfg["trivy"].get("cache_dir", "~/.cache/trivy")) / "policy/content/policies/kubernetes/policies"
        files = list(base.rglob(rego)) if rego else []
        src = files[0] if files else None
    else:
        src = expand(cfg["kubescape"].get("artifacts_dir", "~/.kubescape")) / f"{control.lower()}.json"
        src = src if src.exists() else None
    if src is None:
        return {"control": control, "rule_source": None}
    text = src.read_text(encoding="utf-8", errors="replace")
    if scanner == "kubescape":
        text = "\n".join(r.get("rule", "") for r in json.loads(text).get("rules", []))
    hits = _lines(text, pattern) if pattern else []
    return {"control": control, "rule_source": str(src), "rule_source_sha256": hashlib.sha256(src.read_bytes()).hexdigest()[:16],
            "property_pattern": pattern, f"rule_text_has_{key}": bool(hits), "matching_lines": hits,
            "join_lines": _lines(text, "roleRef") if scanner == "kubescape" else []}


def _violations(case: dict) -> list[dict]:
    a = case.get("assessment") or {}
    return [c for c in a.get("comparisons", []) if c["outcome"] == "violation"]


def family_signature(scanner: str, mr_id: str, violations: list[dict]) -> str:
    """Provisional root-cause family: scanner + MR + verdict transition, independent of how many controls fire.
    Two controls that flip in the same way on the same MR (e.g. C-0267 and C-0272) are ONE family until a human splits it."""
    patterns = sorted({f"{v['source']}->{v['followup']}" for v in violations})
    return f"{scanner}:{mr_id}:{'|'.join(patterns)}"


def _match_known(known: list[dict], scanner: str, mr_id: str, controls: set[str]) -> dict | None:
    for k in known:
        if k["scanner"] == scanner and mr_id in k.get("mrs", [mr_id]) and controls & set(k.get("controls", controls)):
            return k
    return None


def triage_run(run_dir: Path, runner: Runner, cfg: dict, known: list[dict], minimize: bool = False) -> dict:
    rows = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    out = {"scanner": runner.scanner.name, "cases": {}, "note": "candidates only - human confirmation required"}
    for row in rows:
        if row["mr_result"] != R_VIOLATION:
            continue
        cid, mr = row["case_id"], runner.catalog[row["mr_id"]]
        cdir = run_dir / "cases" / cid
        source = load_bundle(cdir / "source", row["seed_id"])
        rerun = runner.run_pair(row["seed_id"], source, mr, row["params"], case_id=cid + "__rerun")
        first = {(v["control"], v["resource"]) for v in _violations(row)}
        again = {(v["control"], v["resource"]) for v in _violations({"assessment": rerun.assessment.to_json() if rerun.assessment else {}})}
        reproduced = rerun.result == R_VIOLATION and first == again
        viol = _violations(row)
        controls = {v["control"] for v in viol}
        km = _match_known(known, runner.scanner.name, row["mr_id"], controls)
        entry = {
            "family": family_signature(runner.scanner.name, row["mr_id"], viol), "reproduced": reproduced,
            "status": "CANDIDATE_REPRODUCED" if reproduced else "NOT_REPRODUCED", "confirmed": False,
            "violating_comparisons": viol, "known_issue": km["url"] if km else None,
            "known_issue_match": "class-level only; root cause NOT verified" if km else None,
            "rule_evidence": [rule_evidence(runner.scanner.name, c, mr, runner.mapping, cfg) for c in sorted(controls)]}
        if reproduced and minimize:
            entry["minimization"] = minimize_case(runner, row["seed_id"], source, mr, row["params"], controls)
        out["cases"][cid] = entry
    (run_dir / "triage.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    write_reproducers(run_dir, out, runner, rows)
    return out


def minimize_case(runner: Runner, seed_id: str, source, mr, params: dict, controls: set[str]) -> dict:
    """Greedy object-level reduction. An object is dropped only if the source stays valid, the pair stays valid and the
    SAME controls still violate. Field-level reduction is out of scope; the result is 'a smaller case found', not minimal."""
    protected = {k for ks in mr.targets(source, params).values() for k in ks}
    cur, tries = source, 0
    changed = True
    while changed:
        changed = False
        for o in list(cur.objects):
            if obj_key(o) in protected:
                continue
            cand = cur.clone()
            cand.objects = [x for x in cand.objects if obj_key(x) != obj_key(o)]
            if cand.problems() or not mr.applicable(cand)[0]:
                continue
            tries += 1
            r = runner.run_pair(seed_id, cand, mr, params, case_id=f"min{tries}__{seed_id}")
            got = {c.control for c in r.assessment.key_results if c.outcome == "violation"} if r.assessment else set()
            if r.result == R_VIOLATION and got == controls:
                cur, changed = cand, True
                break
    return {"objects_before": len(source.objects), "objects_after": len(cur.objects), "attempts": tries,
            "kept": [fmt_key(obj_key(o)) for o in cur.objects], "claim": "smaller case found, not proven minimal"}


def _render_cmd(runner: Runner, scan_dir: str, out_json: str) -> str:
    cmd = runner.scanner.build_command(Path("@DIR@"), Path("@OUT@"))
    s = " ".join(shlex.quote(a) for a in cmd)
    return s.replace("@DIR@", scan_dir).replace("@OUT@", out_json)


def write_reproducers(run_dir: Path, triage: dict, runner: Runner, rows: list[dict]) -> None:
    seen: set[tuple[str, str]] = set()
    by_id = {r["case_id"]: r for r in rows}
    for cid, t in triage["cases"].items():
        key = (t["family"], by_id[cid]["source_sha256"] + by_id[cid]["followup_sha256"])   # one package per unique input pair
        if key in seen:
            continue
        seen.add(key)
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", t["family"]).strip("_")
        d = run_dir / "reproducers" / f"{slug}__{cid}"
        d.mkdir(parents=True, exist_ok=True)
        src = run_dir / "cases" / cid
        for name, dst in (("source/bundle.yaml", "source.yaml"), ("followup/bundle.yaml", "followup.yaml"),
                          ("diff.patch", "transformation.diff"), ("scanner-source.json", "scanner-source.json"),
                          ("scanner-followup.json", "scanner-followup.json"),
                          ("normalized-source.json", "normalized-source.json"),
                          ("normalized-followup.json", "normalized-followup.json"), ("trace.json", "trace.json"),
                          ("assessment.json", "assessment.json")):
            if (src / name).exists():
                (d / dst).write_bytes((src / name).read_bytes())
        row = next(r for r in rows if r["case_id"] == cid)
        (d / "mr-spec.yaml").write_text(yaml.safe_dump(runner.catalog[row["mr_id"]].spec, sort_keys=False, allow_unicode=True), encoding="utf-8")
        (d / "environment.lock.json").write_text(json.dumps(runner.environment_lock(), indent=2), encoding="utf-8")
        controls = sorted({v["control"] for v in t["violating_comparisons"]})
        (d / "triage-notes.md").write_text("\n".join([
            f"# {t['family']}", "", f"- case: `{cid}`  status: **{t['status']}** (not confirmed)",
            f"- known upstream issue: {t['known_issue'] or 'none recorded'}",
            "- violating comparisons:", *[f"  - {v['control']} on {v['resource']}: {v['source']} -> {v['followup']} ({v['reason']})"
                                          for v in t["violating_comparisons"]],
            "", "## Rule-source evidence (static aid, not an oracle)", "",
            "```json", json.dumps(t["rule_evidence"], indent=2), "```", "",
            "## To confirm", "", "1. Re-run `reproduce.sh` on the same pinned version.",
            "2. Read the diff and confirm it does not change the property of the target resource.",
            "3. Read the rule source and decide whether the verdict change is wrong. Only then mark CONFIRMED.", ""]), encoding="utf-8")
        script = "\n".join([
            "#!/usr/bin/env bash", "# Re-runs the real scanner on source.yaml and followup.yaml and prints the verdicts that violated the MR.",
            "set -euo pipefail", 'HERE="$(cd "$(dirname "$0")" && pwd)"; W="$(mktemp -d)"',
            'mkdir -p "$W/source" "$W/followup"; cp "$HERE/source.yaml" "$W/source/bundle.yaml"; cp "$HERE/followup.yaml" "$W/followup/bundle.yaml"',
            _render_cmd(runner, '"$W/source"', '"$W/source.json"') + " >/dev/null 2>&1 || true",
            _render_cmd(runner, '"$W/followup"', '"$W/followup.json"') + " >/dev/null 2>&1 || true",
            f'python3 - "$W" {" ".join(controls)} <<\'PY\'',
            "import json, sys", "w, controls = sys.argv[1], set(sys.argv[2:])",
            "for tag in ('source', 'followup'):", "    d = json.load(open(f'{w}/{tag}.json'))",
            *(["    for r in d.get('results', []):", "        for c in r['controls']:",
               "            if c['controlID'] in controls: print(tag, c['controlID'], c['status']['status'], r['resourceID'][-70:])"]
              if runner.scanner.name == "kubescape" else
              ["    for r in d.get('Results', []):", "        for m in r.get('Misconfigurations', []):",
               "            if m['ID'] in controls: print(tag, m['ID'], m['Status'], m['Message'][:80])"]),
            "PY", 'echo "scan outputs kept in $W"', ""])
        (d / "reproduce.sh").write_text(script, encoding="utf-8")
        (d / "README.md").write_text(
            f"Reproducer for `{t['family']}`. Pinned: {runner.scanner.name} {runner.scanner.cfg.get('version')} "
            f"({runner.scanner.mode}). Run `bash reproduce.sh`. See triage-notes.md.\n", encoding="utf-8")
