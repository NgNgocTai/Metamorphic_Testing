"""MR-04 — flip securityContext.privileged false -> true on exactly one container (controlled change)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import iter_containers, pod_spec
from ..model import ResKey, fmt_key
from .base import implements, key_to_list, list_to_key
from .patterns import Change, ControlledChange


def _path(workload: dict, index: int) -> str:
    return ".".join(pod_spec(workload)[0]) + f".containers[{index}].securityContext.privileged"


@implements("MR-04")
class PrivilegedFlip(ControlledChange):
    rule_probe = ("privileged", r"privileged")
    no_candidates_reason = "no_container_with_explicit_privileged_false"

    def candidates(self, source: ConfigBundle) -> list[tuple[dict, int]]:
        return [(o, i) for o in source.objects for _, i, c in iter_containers(o)
                if (c.get("securityContext") or {}).get("privileged") is False]

    def candidate_params(self, candidate: tuple[dict, int]) -> dict:
        o, i = candidate
        return {"workload": key_to_list(obj_key(o)), "container_index": i}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        wl = fu.index()[list_to_key(params["workload"])]
        pod_spec(wl)[1]["containers"][params["container_index"]]["securityContext"]["privileged"] = True
        return fu, {"operation": "pod.set_privileged_true", "workload": fmt_key(list_to_key(params["workload"])),
                    "path": _path(wl, params["container_index"]), "object_mapping": "identity"}

    def expected_change(self, source: ConfigBundle, params: dict) -> Change | None:
        key = list_to_key(params["workload"])
        wl = source.index().get(key)
        if wl is None or pod_spec(wl) is None:
            return None                     # the exact container named by the params, not "some container"
        return Change(key, _path(wl, params["container_index"]), False, True)

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {"workload": [list_to_key(params["workload"])]}
