"""MR-09 — replace the read verbs of a Secrets rule by a single other read verb (candidate; derived from requirement R08).

Kubernetes RBAC Good Practices: `get`, `list` and `watch` on Secrets each reveal their contents. A rule whose verbs are a non-empty subset of
{get, list, watch} therefore grants the same Secret EXPOSURE whichever subset it names. This is equivalence of the property, not of the API
semantics, so it only holds for controls whose contract is about exposure (KSV-0113, C-0015).
"""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles
from .base import implements, key_to_list, list_to_key
from .patterns import PerCandidateMR

READ_VERBS = ("get", "list", "watch")


def _qualifies(rule: dict) -> bool:
    verbs = rule.get("verbs") or []
    return (rule.get("apiGroups") == [""] and rule.get("resources") == ["secrets"] and not rule.get("resourceNames")
            and bool(verbs) and set(verbs) <= set(READ_VERBS) and len(set(verbs)) == len(verbs))


@implements("MR-09")
class SecretsReadVerbSubstitution(PerCandidateMR):
    no_candidates_reason = "no_role_with_a_core_secrets_rule_using_only_get_list_watch"

    def candidates(self, source: ConfigBundle) -> list[tuple[dict, int, str]]:
        out = []
        for role in source.of_kind("Role"):
            rules = role.get("rules") or []
            if sum(1 for r in rules if "secrets" in (r.get("resources") or [])) != 1:     # the rule must be the only way to reach Secrets
                continue
            for i, rule in enumerate(rules):
                if _qualifies(rule):
                    out += [(role, i, w) for w in READ_VERBS if [w] != rule["verbs"]]
        return out

    def candidate_params(self, candidate: tuple[dict, int, str]) -> dict:
        role, i, w = candidate
        return {"role": key_to_list(obj_key(role)), "rule_index": i, "from_verbs": list(role["rules"][i]["verbs"]), "to_verbs": [w]}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        fu.index()[list_to_key(params["role"])]["rules"][params["rule_index"]]["verbs"] = list(params["to_verbs"])
        return fu, {"operation": "rbac.substitute_secret_read_verbs", "role": fmt_key(list_to_key(params["role"])),
                    "rule_index": params["rule_index"], "from": params["from_verbs"], "to": params["to_verbs"], "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        bad, key, i = "INVALID_PAIR", list_to_key(params["role"]), params["rule_index"]
        s, f = source.index().get(key), followup.index().get(key)
        if s is None or f is None:
            return bad, "target_role_missing"
        if not _qualifies(s["rules"][i]) or s["rules"][i]["verbs"] != params["from_verbs"]:
            return bad, "source_rule_does_not_match_the_parameters"
        expected = {**s["rules"][i], "verbs": list(params["to_verbs"])}
        if f["rules"][i] != expected or f["rules"][:i] != s["rules"][:i] or f["rules"][i + 1:] != s["rules"][i + 1:]:
            return bad, "not_exactly_the_requested_verb_substitution"
        if set(params["to_verbs"]) - set(READ_VERBS) or len(params["to_verbs"]) != 1:
            return bad, "target_verbs_must_be_one_read_verb"
        if any(d.get("object") != fmt_key(key) or not d["path"].startswith(f"rules[{i}].verbs") for d in diff_bundles(source, followup)):
            return bad, "change_outside_the_verbs_of_the_target_rule"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        key = list_to_key(params["role"])
        return {"role_direct": [key], "bound_role": [key]}
