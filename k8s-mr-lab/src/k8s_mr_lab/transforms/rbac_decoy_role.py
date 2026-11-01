"""MR-02 — add an unbound, same-name Role in a fresh namespace (the K1 lesson: Role resolution is namespace-scoped)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import RBAC, local_role_bindings, sa_key, sa_subjects, workloads_using_sa
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles, objects_with_namespace
from .base import MetamorphicRelation, implements

PROFILES = {
    "secrets_read": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
    "wildcard_admin": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}


def _fresh_namespace(source: ConfigBundle, base: str) -> str:
    used = {obj_key(o)[2] for o in source.objects}
    ns, i = f"{base}-decoy", 1
    while ns in used:
        i += 1
        ns = f"{base}-decoy{i}"
    return ns


@implements("MR-02")
class DecoySameNameRole(MetamorphicRelation):
    rule_probe = ("role_namespace_compared", r"role(\.metadata)?\.namespace|roleRef\.namespace")

    def _rolebindings(self, source: ConfigBundle) -> list[dict]:
        return [rb for rb in local_role_bindings(source)
                if any(source.find("ServiceAccount", ns, n) for ns, n in sa_subjects(rb))]

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        if not source.of_kind("RoleBinding"):
            return False, "no_rolebinding"
        if not local_role_bindings(source):
            return False, "no_rolebinding_to_local_role_with_sa_subject"
        if not self._rolebindings(source):
            return False, "no_target_serviceaccount_object"
        return True, ""

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        out = []
        for rb in self._rolebindings(source):
            ns, name = obj_key(rb)[2], obj_key(rb)[3]
            for profile in PROFILES:
                out.append({"rolebinding": name, "namespace": ns, "role": rb["roleRef"]["name"],
                            "decoy_namespace": _fresh_namespace(source, ns), "profile": profile})
        return out[:max_cases]

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        decoy = {"apiVersion": f"{RBAC}/v1", "kind": "Role",
                 "metadata": {"name": params["role"], "namespace": params["decoy_namespace"]},
                 "rules": [dict(r) for r in PROFILES[params["profile"]]]}
        fu.objects.append(decoy)
        return fu, {"operation": "rbac.add_unbound_same_name_role", "added": fmt_key(obj_key(decoy)),
                    "profile": params["profile"], "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        bad = "INVALID_PAIR"
        d = diff_bundles(source, followup)
        if len(d) != 1 or d[0]["op"] != "add_object":
            return bad, "diff_is_not_exactly_one_added_object"
        if (RBAC, "Role", params["decoy_namespace"], params["role"]) not in followup.index():
            return bad, "decoy_role_missing_or_misnamed"
        if params["decoy_namespace"] in {obj_key(o)[2] for o in source.objects}:
            return bad, "decoy_namespace_not_fresh"
        if len(objects_with_namespace(followup, params["decoy_namespace"])) != 1:
            return bad, "decoy_namespace_contains_other_objects"
        if len(followup.of_kind("RoleBinding", "ClusterRoleBinding")) != len(source.of_kind("RoleBinding", "ClusterRoleBinding")):
            return bad, "binding_count_changed"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        ns, role = params["namespace"], params["role"]
        rb = source.find("RoleBinding", ns, params["rolebinding"])
        sas = [sa_key(n, s) for n, s in sa_subjects(rb) if source.find("ServiceAccount", n, s)]
        wl = [w for n, s in sa_subjects(rb) for w in workloads_using_sa(source, n, s)]
        return {"bound_role": [(RBAC, "Role", ns, role)], "subject_sa": sas, "workload": wl,
                "rolebinding": [obj_key(rb)]}
