"""MR-08 — move a ServiceAccount subject to another namespace (candidate): the workload must lose the permission.

A ServiceAccount subject names (namespace, name). The follow-up changes only `subjects[i].namespace` to a fresh namespace and adds the
ServiceAccount there so the subject is not dangling. The workload keeps running as the original ServiceAccount, which the binding no
longer names. KP3 with one companion object, so the pair is validated here instead of by expect_single_change.
"""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import other_bindings_naming_sa, sa_key, workloads_using_sa
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles, expect_single_change
from .base import implements, key_to_list, list_to_key
from .patterns import Change, ControlledChange


def _fresh_namespace(source: ConfigBundle, base: str) -> str:
    used = {obj_key(o)[2] for o in source.objects}
    ns, i = f"{base}-shifted", 1
    while ns in used:
        i += 1
        ns = f"{base}-shifted{i}"
    return ns


@implements("MR-08")
class SubjectNamespaceShift(ControlledChange):
    no_candidates_reason = "no_sole_binding_of_a_serviceaccount_used_by_a_workload"

    def candidates(self, source: ConfigBundle) -> list[tuple[dict, int]]:
        out = []
        for rb in source.of_kind("RoleBinding"):
            ns, ref = obj_key(rb)[2], rb.get("roleRef") or {}
            if ref.get("kind") != "Role" or not source.find("Role", ns, ref.get("name", "")):
                continue
            for i, s in enumerate(rb.get("subjects") or []):
                sns, name = s.get("namespace"), s.get("name")
                if (s.get("kind") == "ServiceAccount" and name and sns and source.find("ServiceAccount", sns, name)
                        and workloads_using_sa(source, sns, name)                     # the verdict that must change is the workload's
                        and not other_bindings_naming_sa(source, obj_key(rb), sns, name)   # no other path (closed-bundle premise)
                        and len(rb["subjects"]) == 1):                                # one subject: nothing else keeps the binding relevant
                    out.append((rb, i))
        return out

    def candidate_params(self, candidate: tuple[dict, int]) -> dict:
        rb, i = candidate
        return {"rolebinding": key_to_list(obj_key(rb)), "subject_index": i, "serviceaccount": rb["subjects"][i]["name"],
                "from_namespace": rb["subjects"][i]["namespace"]}

    def _new_ns(self, source: ConfigBundle, params: dict) -> str:
        return _fresh_namespace(source, params["from_namespace"])

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        new_ns = self._new_ns(source, params)
        fu.index()[list_to_key(params["rolebinding"])]["subjects"][params["subject_index"]]["namespace"] = new_ns
        fu.objects.append({"apiVersion": "v1", "kind": "ServiceAccount",
                           "metadata": {"name": params["serviceaccount"], "namespace": new_ns}})
        return fu, {"operation": "rbac.shift_serviceaccount_subject_namespace", "rolebinding": fmt_key(list_to_key(params["rolebinding"])),
                    "from_namespace": params["from_namespace"], "to_namespace": new_ns, "added": f"ServiceAccount/{new_ns}/{params['serviceaccount']}",
                    "object_mapping": "identity"}

    def expected_change(self, source: ConfigBundle, params: dict) -> Change:
        return Change(list_to_key(params["rolebinding"]), f"subjects[{params['subject_index']}].namespace",
                      params["from_namespace"], self._new_ns(source, params))

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        """KP3 check on the one changed field, plus: the only other difference is the companion ServiceAccount."""
        new_ns = self._new_ns(source, params)
        companion = fmt_key(sa_key(new_ns, params["serviceaccount"]))
        diff = diff_bundles(source, followup)
        added = [d for d in diff if d["op"] == "add_object"]
        if len(added) != 1 or added[0]["object"] != companion:
            return "INVALID_PAIR", "the_only_added_object_must_be_the_serviceaccount_in_the_new_namespace"
        status, why = expect_single_change([d for d in diff if d["op"] != "add_object"], *self.expected_change(source, params))
        if status != VALID_PAIR:
            return status, why
        if workloads_using_sa(followup, params["from_namespace"], params["serviceaccount"]) != workloads_using_sa(source, params["from_namespace"], params["serviceaccount"]):
            return "INVALID_PAIR", "workload_assignment_changed"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {"workload": workloads_using_sa(source, params["from_namespace"], params["serviceaccount"])}
