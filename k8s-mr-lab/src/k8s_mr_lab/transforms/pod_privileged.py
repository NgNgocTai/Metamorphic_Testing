"""MR-04 — flip securityContext.privileged false -> true on exactly one container (controlled change)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import iter_containers, pod_spec
from ..model import ResKey, VALID_PAIR, fmt_key
from ..validation import diff_bundles
from .base import MetamorphicRelation, key_to_list, list_to_key


class PrivilegedFlip(MetamorphicRelation):
    id = "MR-04"
    name = "privileged-flip"
    category = "R9"
    property = "container_privileged"
    relation = "pass_to_fail"

    def _candidates(self, source: ConfigBundle) -> list[tuple[dict, int]]:
        out = []
        for o in source.objects:
            for _, i, c in iter_containers(o):
                if (c.get("securityContext") or {}).get("privileged") is False:
                    out.append((o, i))
        return out

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        return (True, "") if self._candidates(source) else (False, "no_container_with_explicit_privileged_false")

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        return [{"workload": key_to_list(obj_key(o)), "container_index": i} for o, i in self._candidates(source)][:max_cases]

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        wl = fu.index()[list_to_key(params["workload"])]
        path, spec = pod_spec(wl)
        c = spec["containers"][params["container_index"]]
        c["securityContext"]["privileged"] = True
        return fu, {"operation": "pod.set_privileged_true", "workload": fmt_key(list_to_key(params["workload"])),
                    "path": ".".join(path) + f".containers[{params['container_index']}].securityContext.privileged",
                    "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        key = list_to_key(params["workload"])
        d = diff_bundles(source, followup)
        if len(d) != 1:
            return "INVALID_PAIR", f"expected_exactly_one_change_got_{len(d)}"
        c = d[0]
        if c["object"] != fmt_key(key):
            return "INVALID_PAIR", "change_on_wrong_object"
        ps = pod_spec(source.index()[key])
        if ps is None:
            return "INVALID_PAIR", "target_is_not_a_workload"
        # the exact container named by the parameters, not merely "some container of that workload"
        expected = ".".join(ps[0]) + f".containers[{params['container_index']}].securityContext.privileged"
        if c["path"] != expected:
            return "INVALID_PAIR", f"change_on_{c['path']}_expected_{expected}"
        if (c["op"], c["old"], c["new"]) != ("change", False, True):
            return "INVALID_PAIR", "change_is_not_privileged_false_to_true"
        return VALID_PAIR, ""

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {"workload": [list_to_key(params["workload"])]}
