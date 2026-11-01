"""MR relation checker: the metamorphic oracle. It only ever sees normalized verdicts of ONE scanner on C1 and C2."""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from .bundles import ConfigBundle, obj_key
from .k8s import rbac_triple_members
from .model import (CONCLUSIVE, EQUAL, FAIL, FAIL_TO_PASS, PASS, PASS_TO_FAIL, R_INCONCLUSIVE, R_PARTIAL, R_PASS,
                    R_SKIP, R_VIOLATION, Assessment, KeyResult, NormalizedReport, ResKey)
from .transforms.base import MetamorphicRelation

if TYPE_CHECKING:
    from .registry import MappingEntry

ALL_OF_KIND = "ALL_OF_KIND"
Key = tuple[str, ResKey]

# Named contract rules a control registry entry may declare (`scope_rule`): the objects of the rule's kinds the control CAN judge in a
# given bundle. An object outside the rule is out of the control's scope (never compared, recorded in scope.json); an object inside
# it that the scanner does not evaluate is a missing verdict and stays INCONCLUSIVE.
SCOPE_RULES: dict[str, tuple[frozenset[str], Callable[[ConfigBundle], set[ResKey]]]] = {
    "rbac_triple_member": (frozenset({"ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}), rbac_triple_members),
}


def static_keys(mr: MetamorphicRelation, entries: list[MappingEntry], control_kinds: dict[str, list[str]],
                source: ConfigBundle, params: dict, scope_rules: dict[str, str] | None = None,
                excluded: list | None = None) -> list[Key]:
    """Comparison keys derivable before scanning: mapped controls x target resources, filtered by the kinds the control reports on
    and by its `scope_rule` (control -> rule name). Keys dropped by a scope rule are appended to `excluded` as (control, key, rule)."""
    members: dict[str, set[ResKey]] = {}
    targets = mr.targets(source, params)
    undeclared = set(targets) - set(mr.spec["targets"])
    if undeclared:
        raise ValueError(f"{mr.id}: targets() returned {sorted(undeclared)}, not declared in the catalog (targets: {mr.spec['targets']})")
    keys: list[Key] = []
    for e in entries:
        kinds = control_kinds.get(e.control)
        cands = [obj_key(o) for o in source.objects] if e.target == ALL_OF_KIND else targets.get(e.target, [])
        rule = (scope_rules or {}).get(e.control)
        for k in cands:
            if not (kinds is None or k[1] in kinds) or (e.control, k) in keys:
                continue
            if rule:
                rkinds, fn = SCOPE_RULES[rule]
                if k[1] in rkinds:
                    ms = members.setdefault(rule, fn(source))
                    if k not in ms:
                        if excluded is not None and (e.control, k, rule) not in excluded:
                            excluded.append((e.control, k, rule))
                        continue
            keys.append((e.control, k))
    return keys


def full_keys(mr: MetamorphicRelation, static: list[Key], r1: NormalizedReport, r2: NormalizedReport) -> list[Key]:
    keys = list(static)
    if mr.all_failures:
        for k in sorted(r1.failed_keys() | r2.failed_keys(), key=lambda x: (x[0], x[1])):
            if k not in keys:
                keys.append(k)
    return keys


def _equal(a: str, b: str) -> tuple[str, str]:
    return ("ok", "") if a == b else ("violation", f"{a}->{b} but relation requires equality")


def _transition(want_from: str, want_to: str) -> Callable[[str, str], tuple[str, str]]:
    def rel(a: str, b: str) -> tuple[str, str]:
        if a != want_from:
            return "inconclusive", f"baseline_precondition_not_met: source is {a}, relation needs {want_from}"
        return ("ok", "") if b == want_to else ("violation", f"{a}->{b} but relation requires {want_from}->{want_to}")
    return rel


# name -> judge(source_status, followup_status) for two CONCLUSIVE verdicts. Register a custom predicate here when an
# MR needs one; missing/inconclusive verdicts are handled once, in _compare, for every relation.
RELATIONS: dict[str, Callable[[str, str], tuple[str, str]]] = {
    EQUAL: _equal,
    PASS_TO_FAIL: _transition(PASS, FAIL),
    FAIL_TO_PASS: _transition(FAIL, PASS),
}


def _compare(relation: str, a: str, b: str) -> tuple[str, str]:
    """Return (outcome, reason) for one (control, resource): ok | violation | inconclusive."""
    if a not in CONCLUSIVE:
        return "inconclusive", f"source_verdict_{a.lower()}"
    if b not in CONCLUSIVE:
        return "inconclusive", f"followup_verdict_{b.lower()}"
    return RELATIONS[relation](a, b)


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
        inferred = any(str(e).startswith("pass_inferred") for v in (v1, v2) for e in v.evidence)
        res.key_results.append(KeyResult(control, rk, v1.status, v2.status, outcome, reason, inferred))
    c = res.counts()
    if c["violation"]:
        res.result, res.reason = R_VIOLATION, f"{c['violation']} comparison(s) violate relation '{mr.relation}'"
    elif c["ok"] and not c["inconclusive"]:
        res.result, res.reason = R_PASS, f"all {c['ok']} comparison(s) satisfy '{mr.relation}'"
    elif c["ok"]:
        # Never a full PASS while part of the scope had no usable verdict.
        res.result, res.reason = R_PARTIAL, (f"{c['ok']} comparison(s) satisfy '{mr.relation}' but "
                                             f"{c['inconclusive']} had no usable verdict")
    else:
        res.result, res.reason = R_INCONCLUSIVE, "no conclusive comparison (all verdicts missing or baseline unmet)"
    return res
