"""Reporting layer: which compared (control, resource) keys could actually have reacted to the change an MR made?

An MR PASS only means the relation held. If the compared control cannot observe the changed object, the relation holds by
construction and says nothing about the scanner. This module classifies every comparison of a saved run; it reads evidence
(`cases/*/diff.json`, `assessment.json`) and the control registry (`config/control-registry.yaml`, derived from the pinned policy).
It never changes a verdict, a result or the checker. The Runner calls `annotate` on every assessment it produces, so the tier is part of
the official result of a run; `analyze_run` applies the same function to saved evidence.

Relation satisfied / violated (the checker's `outcome`) and "the verdict could observe the property" (the tier) are separate columns:
a satisfied relation on an UNINFORMATIVE comparison is not evidence about the scanner.

Tiers (first match wins):
  INCONCLUSIVE   a verdict is missing on a side, or the baseline precondition of a directional relation was not met
  CONTROL        a deliberate negative control (mapping role `control`): it must NOT react; a VIOLATION is UNEXPECTED_VIOLATION
  UNINFORMATIVE  comparable, but the control cannot observe any changed object (equal-by-construction); a VIOLATION here is an
                 anomaly (UNEXPECTED_VIOLATION) because nothing it can read changed
  WEAK           comparable and observable, but a PASS on either side is inferred (Trivy: absence of an attributed FAIL)
  INFORMATIVE    comparable, observable, and every PASS involved is explicit; a FAIL is positive evidence on its own

`observable` is a NECESSARY condition derived from the control's input model, not proof that the rego depends on the changed field.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .model import Assessment

INCONCLUSIVE, UNINFORMATIVE, WEAK, INFORMATIVE, CONTROL = "INCONCLUSIVE", "UNINFORMATIVE", "WEAK", "INFORMATIVE", "CONTROL"
TIERS = (INFORMATIVE, WEAK, CONTROL, UNINFORMATIVE, INCONCLUSIVE)
CONCLUSIVE = ("PASS", "FAIL")
ALL = "*"                      # text-only rewrite (empty structural diff): every object was re-serialised


def _kind(resource: str) -> str:
    return resource.split("/", 1)[0]


def changed_objects(diff: list[dict]) -> list[str]:
    """Object strings (`Kind/ns/name@group`) touched by a case; [ALL] when the diff is empty (representation rewrite)."""
    objs = sorted({d["object"] for d in diff})
    return objs or [ALL]


def observable(scanner: str, control: str, resource: str, changed: list[str], mapping) -> bool:
    if changed == [ALL]:
        return True
    meta = mapping.control_meta(scanner, control)
    if not meta:
        raise KeyError(f"no registry entry for {scanner}/{control} in control-registry.yaml")
    if meta["scope"] == "judged_object":                 # sees only the document it judges
        return resource in changed
    kinds = set(meta["reads"])                           # all_matched_kinds: any changed kind is loaded into the rego input
    return any(_kind(o) in kinds for o in changed)


def classify(scanner: str, comp: dict, changed: list[str], mapping, role: str = "property") -> tuple[str, str]:
    """Return (tier, note) for one comparison record of assessment.json."""
    s, f = comp["source"], comp["followup"]
    if s not in CONCLUSIVE or f not in CONCLUSIVE or comp["outcome"] == "inconclusive":
        return INCONCLUSIVE, comp.get("reason", "")
    if role == "control":
        return CONTROL, "UNEXPECTED_VIOLATION" if comp["outcome"] == "violation" else "negative control stayed unchanged"
    if not observable(scanner, comp["control"], comp["resource"], changed, mapping):
        return UNINFORMATIVE, "UNEXPECTED_VIOLATION" if comp["outcome"] == "violation" else "control cannot observe the changed object"
    if comp["outcome"] != "violation" and comp.get("basis") == "inferred_pass" and "PASS" in (s, f):
        return WEAK, "PASS inferred (absence of an attributed FAIL)"
    return INFORMATIVE, ""


def roles(mapping, mr_id: str, scanner: str) -> dict[str, str]:
    return {e.control: e.role for e in mapping.entries(mr_id, scanner)}


def annotate(a: Assessment, mapping, scanner: str, mr_id: str, changed: list[str]) -> None:
    """Set role / tier / note / engaged on every KeyResult of a fresh assessment (the Runner calls this for every case)."""
    role = roles(mapping, mr_id, scanner)
    for k, c in zip(a.key_results, a.to_json()["comparisons"]):
        k.role = role.get(k.control, "property")
        k.tier, k.note = classify(scanner, c, changed, mapping, k.role)
        k.engaged = "FAIL" in (k.source, k.followup)


def analyze_run(run_dir: str | Path, mapping) -> list[dict]:
    """One row per comparison. Requires `cases/` (a run directory or a packaged evidence directory)."""
    run = Path(run_dir)
    scanner = json.loads((run / "environment.lock.json").read_text(encoding="utf-8"))["scanner"]
    rows: list[dict] = []
    for case in sorted((run / "cases").iterdir()):
        asm = json.loads((case / "assessment.json").read_text(encoding="utf-8"))
        comps = (asm.get("assessment") or {}).get("comparisons")
        if comps is None:
            continue
        diff = json.loads((case / "diff.json").read_text(encoding="utf-8"))
        changed = changed_objects(diff)
        mr_id = case.name.split("__", 1)[0]
        role = roles(mapping, mr_id, scanner)
        for c in comps:
            tier, note = classify(scanner, c, changed, mapping, role.get(c["control"], "property"))
            rows.append({"scanner": scanner, "case_id": case.name, "mr_id": mr_id, "control": c["control"], "resource": c["resource"],
                         "source": c["source"], "followup": c["followup"],
                         "role": role.get(c["control"], "property"), "outcome": c["outcome"], "basis": c.get("basis", ""),
                         "changed": ";".join(changed), "tier": tier, "note": note,
                         "engaged": "FAIL" in (c["source"], c["followup"])})
    return rows


def summarize(rows: list[dict]) -> dict:
    """Counts by scanner and MR. `informative_rate` = INFORMATIVE / all comparisons (a share of a stated denominator, not a score)."""
    out: dict = {}
    for key_fn, name in ((lambda r: (r["scanner"], "ALL"), "all"), (lambda r: (r["scanner"], r["mr_id"]), "by_mr")):
        groups: dict = {}
        for r in rows:
            groups.setdefault(key_fn(r), Counter())[r["tier"]] += 1
        out[name] = {f"{k[0]}/{k[1]}": {**{t: c.get(t, 0) for t in TIERS}, "total": sum(c.values()),
                                       "informative_rate": round(c.get(INFORMATIVE, 0) / sum(c.values()), 3)}
                     for k, c in sorted(groups.items())}
    # WEAK rows where a FAIL is attributed to the resource on one side: the check demonstrably reacts there (e.g. Trivy PASS(inferred) -> FAIL)
    out["weak_but_engaged"] = {f"{k[0]}/{k[1]}": n for k, n in sorted(Counter((r["scanner"], r["mr_id"]) for r in rows if r["tier"] == WEAK and r["engaged"]).items())}
    out["unexpected_violations"] = [r["case_id"] + ":" + r["control"] for r in rows if r["note"] == "UNEXPECTED_VIOLATION"]
    return out


def write_csv(rows: list[dict], path: str | Path) -> None:
    cols = ["scanner", "case_id", "mr_id", "control", "resource", "source", "followup", "role", "outcome", "basis", "changed", "tier", "note", "engaged"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows(rows)
