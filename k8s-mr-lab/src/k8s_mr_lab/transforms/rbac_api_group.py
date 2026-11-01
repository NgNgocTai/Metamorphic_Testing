"""MR-05 — move the only (core) Secrets read rule to a non-core API group (controlled change)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import READ_VERBS, bound_service_accounts, secret_read_granted_elsewhere, workloads_of_service_accounts
from ..model import ResKey, fmt_key
from .base import implements, key_to_list, list_to_key
from .patterns import Change, ControlledChange


def _is_sole_core_secrets_read(role: dict) -> bool:
    rules = role.get("rules") or []
    if len(rules) != 1:
        return False
    r = rules[0]
    return (r.get("apiGroups") == [""] and r.get("resources") == ["secrets"] and not r.get("resourceNames")
            and bool(r.get("verbs")) and set(r["verbs"]) <= READ_VERBS)


@implements("MR-05")
class ApiGroupSwitch(ControlledChange):
    rule_probe = ("apiGroups", r"apiGroups")
    no_candidates_reason = "no_role_whose_only_rule_reads_core_secrets"

    def candidates(self, source: ConfigBundle) -> list[dict]:
        return [r for r in source.of_kind("Role") if _is_sole_core_secrets_read(r)]

    def candidate_params(self, candidate: dict) -> dict:
        return {"role": key_to_list(obj_key(candidate))}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        fu.index()[list_to_key(params["role"])]["rules"][0]["apiGroups"] = ["apps"]
        return fu, {"operation": "rbac.switch_api_group", "role": fmt_key(list_to_key(params["role"])),
                    "from": [""], "to": ["apps"], "object_mapping": "identity"}

    def expected_change(self, source: ConfigBundle, params: dict) -> Change:
        return Change(list_to_key(params["role"]), "rules[0].apiGroups[0]", "", "apps")

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        key = list_to_key(params["role"])
        role = source.index()[key]
        sas = bound_service_accounts(source, role)
        out = {"role_direct": [key]}          # controls that judge this Role itself (e.g. Trivy KSV-0113)
        if secret_read_granted_elsewhere(source, role, sas):
            return out                        # subject/workload-level controls would be judged on the wrong premise
        return {**out, "bound_role": [key], "subject_sa": sas, "workload": workloads_of_service_accounts(source, sas)}
