"""MR-03 — split one RBAC rule into one rule per verb. RBAC is additive, so the permission tuples are unchanged."""
from __future__ import annotations

import copy

from ..bundles import ConfigBundle, obj_key
from ..k8s import bound_service_accounts, permission_tuples, workloads_of_service_accounts
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles
from .base import implements, key_to_list, list_to_key
from .patterns import PerCandidateMR


@implements("MR-03")
class SplitRuleVerbs(PerCandidateMR):
    no_candidates_reason = "no_rule_with_two_or_more_distinct_verbs"

    def candidates(self, source: ConfigBundle) -> list[tuple[dict, int]]:
        return [(role, i) for role in source.of_kind("Role", "ClusterRole") for i, rule in enumerate(role.get("rules") or [])
                if len(rule.get("verbs") or []) >= 2 and len(set(rule["verbs"])) == len(rule["verbs"])]

    def candidate_params(self, candidate: tuple[dict, int]) -> dict:
        role, i = candidate
        return {"role": key_to_list(obj_key(role)), "rule_index": i}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        role = fu.index()[list_to_key(params["role"])]
        i = params["rule_index"]
        rule = role["rules"][i]
        pieces = []
        for v in rule["verbs"]:
            p = copy.deepcopy(rule)
            p["verbs"] = [v]
            pieces.append(p)
        role["rules"][i:i + 1] = pieces
        return fu, {"operation": "rbac.split_rule_verbs", "role": fmt_key(list_to_key(params["role"])),
                    "rule_index": i, "pieces": len(pieces), "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        bad, key = "INVALID_PAIR", list_to_key(params["role"])
        s, f = source.index().get(key), followup.index().get(key)
        if s is None or f is None:
            return bad, "target_role_missing"
        if permission_tuples(s) != permission_tuples(f):
            return bad, "permission_tuples_changed"
        if len(f["rules"]) <= len(s["rules"]):
            return bad, "rule_count_did_not_increase"
        # exactly the requested split: rule i became one rule per verb, every other rule is untouched
        i, verbs = params["rule_index"], s["rules"][params["rule_index"]]["verbs"]
        expected = [{**s["rules"][i], "verbs": [v]} for v in verbs]
        if f["rules"][:i] != s["rules"][:i] or f["rules"][i:i + len(verbs)] != expected or f["rules"][i + len(verbs):] != s["rules"][i + 1:]:
            return bad, "not_exactly_the_requested_split"
        if any(d.get("object") != fmt_key(key) or not d["path"].startswith("rules") for d in diff_bundles(source, followup)):
            return bad, "change_outside_target_role_rules"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        key = list_to_key(params["role"])
        role = source.index()[key]
        sas = bound_service_accounts(source, role)
        return {"bound_role": [key], "subject_sa": sas, "workload": workloads_of_service_accounts(source, sas)}
