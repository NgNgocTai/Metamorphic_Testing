"""MR relation checker: the metamorphic oracle. It only ever sees normalized verdicts of ONE scanner on C1 and C2."""
from __future__ import annotations

from .bundles import ConfigBundle, obj_key
from .model import (CONCLUSIVE, EQUAL, FAIL, FAIL_TO_PASS, PASS, PASS_TO_FAIL, R_INCONCLUSIVE, R_PASS, R_SKIP,
                    R_VIOLATION, Assessment, KeyResult, NormalizedReport, ResKey)
from .registry import MappingEntry
from .transforms.base import MetamorphicRelation

ALL_OF_KIND = "ALL_OF_KIND"
Key = tuple[str, ResKey]


def static_keys(mr: MetamorphicRelation, entries: list[MappingEntry], control_kinds: dict[str, list[str]],
                source: ConfigBundle, params: dict) -> list[Key]:
    """Comparison keys derivable before scanning: mapped controls x target resources (kind-filtered)."""
    targets = mr.targets(source, params)
    keys: list[Key] = []
    for e in entries:
        kinds = control_kinds.get(e.control)
        cands = [obj_key(o) for o in source.objects] if e.target == ALL_OF_KIND else targets.get(e.target, [])
        for k in cands:
            if (kinds is None or k[1] in kinds) and (e.control, k) not in keys:
                keys.append((e.control, k))
    return keys


def full_keys(mr: MetamorphicRelation, static: list[Key], r1: NormalizedReport, r2: NormalizedReport) -> list[Key]:
    keys = list(static)
    if mr.all_failures:
        for k in sorted(r1.failed_keys() | r2.failed_keys(), key=lambda x: (x[0], x[1])):
            if k not in keys:
                keys.append(k)
    return keys


def _compare(relation: str, a: str, b: str) -> tuple[str, str]:
    """Return (outcome, reason) for one (control, resource): ok | violation | inconclusive."""
    if a not in CONCLUSIVE:
        return "inconclusive", f"source_verdict_{a.lower()}"
    if b not in CONCLUSIVE:
        return "inconclusive", f"followup_verdict_{b.lower()}"
    if relation == EQUAL:
        return ("ok", "") if a == b else ("violation", f"{a}->{b} but relation requires equality")
    want_from, want_to = (PASS, FAIL) if relation == PASS_TO_FAIL else (FAIL, PASS)
    if a != want_from:
        return "inconclusive", f"baseline_precondition_not_met: source is {a}, relation needs {want_from}"
    return ("ok", "") if b == want_to else ("violation", f"{a}->{b} but relation requires {want_from}->{want_to}")


def check(mr: MetamorphicRelation, keys: list[Key], r1: NormalizedReport, r2: NormalizedReport) -> Assessment:
    if r1.unattributed_failures or r2.unattributed_failures:
        # A failure we cannot place on a resource could hide or fake a difference: refuse to conclude.
        why = (r1.unattributed_failures + r2.unattributed_failures)[0]
        return Assessment(R_INCONCLUSIVE, mr.relation, f"unattributed failure: {why}")
    if not keys:
        return Assessment(R_SKIP, mr.relation, "no_comparable_keys")
    res = Assessment(R_INCONCLUSIVE, mr.relation)
    for control, rk in keys:
        v1, v2 = r1.get(control, rk), r2.get(control, rk)
        outcome, reason = _compare(mr.relation, v1.status, v2.status)
        res.key_results.append(KeyResult(control, rk, v1.status, v2.status, outcome, reason))
    c = res.counts()
    if c["violation"]:
        res.result, res.reason = R_VIOLATION, f"{c['violation']} comparison(s) violate relation '{mr.relation}'"
    elif c["ok"]:
        res.result, res.reason = R_PASS, f"{c['ok']} conclusive comparison(s) satisfy '{mr.relation}'" + (
            f"; {c['inconclusive']} inconclusive" if c["inconclusive"] else "")
    else:
        res.result, res.reason = R_INCONCLUSIVE, "no conclusive comparison (all verdicts missing or baseline unmet)"
    return res
