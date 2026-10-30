"""MR-05 — move the only (core) Secrets read rule to a non-core API group (controlled change)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import READ_VERBS, bound_service_accounts, workloads_using_sa
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles
from .base import MetamorphicRelation, key_to_list, list_to_key


class ApiGroupSwitch(MetamorphicRelation):
    id = "MR-05"
    name = "api-group-switch"
    category = "R3"
    property = "core_secrets_read_permission"
    relation = "fail_to_pass"

    @staticmethod
    def _is_sole_core_secrets_read(role: dict) -> bool:
        rules = role.get("rules") or []
        if len(rules) != 1:
            return False
        r = rules[0]
        return (r.get("apiGroups") == [""] and r.get("resources") == ["secrets"] and not r.get("resourceNames")
                and bool(r.get("verbs")) and set(r["verbs"]) <= READ_VERBS)

    def _candidates(self, source: ConfigBundle) -> list[dict]:
        return [r for r in source.of_kind("Role") if self._is_sole_core_secrets_read(r)]

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        return (True, "") if self._candidates(source) else (False, "no_role_whose_only_rule_reads_core_secrets")

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        return [{"role": key_to_list(obj_key(r))} for r in self._candidates(source)][:max_cases]

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        fu.index()[list_to_key(params["role"])]["rules"][0]["apiGroups"] = ["apps"]
        return fu, {"operation": "rbac.switch_api_group", "role": fmt_key(list_to_key(params["role"])),
                    "from": [""], "to": ["apps"], "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        key = list_to_key(params["role"])
        d = diff_bundles(source, followup)
        if len(d) != 1:
            return "INVALID_PAIR", f"expected_exactly_one_change_got_{len(d)}"
        c = d[0]
        if c["object"] != fmt_key(key) or c["path"] != "rules[0].apiGroups[0]" or (c["old"], c["new"]) != ("", "apps"):
            return "INVALID_PAIR", "change_is_not_core_to_apps_on_target_rule"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        key = list_to_key(params["role"])
        sas = bound_service_accounts(source, source.index()[key])
        wl = [w for (_, _, ns, n) in sas for w in workloads_using_sa(source, ns, n)]
        return {"bound_role": [key], "subject_sa": sas, "workload": wl}
