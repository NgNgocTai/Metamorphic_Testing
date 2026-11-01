"""MR-07 — rewrite a ServiceAccount subject as the equivalent User subject `system:serviceaccount:<ns>:<name>` (candidate).

A service account authenticates with exactly that username, and an RBAC User subject matches the authenticated username,
so the binding grants the same permissions to the same identity. Only one subject of one RoleBinding is rewritten.
"""
from __future__ import annotations

import copy

from ..bundles import ConfigBundle, obj_key
from ..k8s import RBAC, sa_key, workloads_using_sa
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles
from .base import MetamorphicRelation, implements, key_to_list, list_to_key


def as_user(namespace: str, name: str) -> dict:
    return {"kind": "User", "apiGroup": RBAC, "name": f"system:serviceaccount:{namespace}:{name}"}


@implements("MR-07")
class ServiceAccountSubjectAsUser(MetamorphicRelation):
    def _candidates(self, source: ConfigBundle) -> list[tuple[dict, int]]:
        out = []
        for rb in source.of_kind("RoleBinding"):
            ns, ref = obj_key(rb)[2], rb.get("roleRef") or {}
            if ref.get("kind") != "Role" or not source.find("Role", ns, ref.get("name", "")):
                continue
            for i, s in enumerate(rb.get("subjects") or []):
                # explicit namespace only: never rely on defaulting of the subject namespace
                if (s.get("kind") == "ServiceAccount" and s.get("name") and s.get("namespace")
                        and source.find("ServiceAccount", s["namespace"], s["name"])):
                    out.append((rb, i))
        return out

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        if self._candidates(source):
            return True, ""
        return False, "no_rolebinding_to_local_role_with_explicit_serviceaccount_subject_present_in_bundle"

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        return [{"rolebinding": key_to_list(obj_key(rb)), "subject_index": i} for rb, i in self._candidates(source)][:max_cases]

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        rb = fu.index()[list_to_key(params["rolebinding"])]
        old = rb["subjects"][params["subject_index"]]
        new = as_user(old["namespace"], old["name"])
        rb["subjects"][params["subject_index"]] = new
        return fu, {"operation": "rbac.serviceaccount_subject_as_user", "rolebinding": fmt_key(list_to_key(params["rolebinding"])),
                    "subject_index": params["subject_index"], "from": old, "to": new, "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        key, i = list_to_key(params["rolebinding"]), params["subject_index"]
        s, f = source.index().get(key), followup.index().get(key)
        if s is None or f is None:
            return "INVALID_PAIR", "target_rolebinding_missing"
        old = s["subjects"][i]
        if f["subjects"][i] != as_user(old["namespace"], old["name"]):
            return "INVALID_PAIR", "subject_is_not_the_equivalent_user"
        restored = copy.deepcopy(f)
        restored["subjects"][i] = old
        if restored != s:
            return "INVALID_PAIR", "rolebinding_changed_beyond_the_subject"
        if any(d.get("object") != fmt_key(key) for d in diff_bundles(source, followup)):
            return "INVALID_PAIR", "change_outside_target_rolebinding"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        key = list_to_key(params["rolebinding"])
        rb = source.index()[key]
        sub = rb["subjects"][params["subject_index"]]
        role = (RBAC, "Role", key[2], rb["roleRef"]["name"])
        return {"bound_role": [role], "subject_sa": [sa_key(sub["namespace"], sub["name"])],
                "workload": workloads_using_sa(source, sub["namespace"], sub["name"]), "rolebinding": [key]}
