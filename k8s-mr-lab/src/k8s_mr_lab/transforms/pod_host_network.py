"""MR-06 — flip spec.hostNetwork false -> true on exactly one workload (controlled change, candidate)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..k8s import pod_spec
from ..model import ResKey, fmt_key
from .base import implements, key_to_list, list_to_key
from .patterns import Change, ControlledChange


def _path(workload: dict) -> str:
    return ".".join(pod_spec(workload)[0]) + ".hostNetwork"


@implements("MR-06")
class HostNetworkFlip(ControlledChange):
    no_candidates_reason = "no_workload_with_explicit_hostnetwork_false"

    def candidates(self, source: ConfigBundle) -> list[dict]:
        return [o for o in source.objects if (ps := pod_spec(o)) and ps[1].get("hostNetwork") is False]

    def candidate_params(self, candidate: dict) -> dict:
        return {"workload": key_to_list(obj_key(candidate))}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        wl = fu.index()[list_to_key(params["workload"])]
        pod_spec(wl)[1]["hostNetwork"] = True
        return fu, {"operation": "pod.set_host_network_true", "workload": fmt_key(list_to_key(params["workload"])),
                    "path": _path(wl), "object_mapping": "identity"}

    def expected_change(self, source: ConfigBundle, params: dict) -> Change | None:
        key = list_to_key(params["workload"])
        wl = source.index().get(key)
        return Change(key, _path(wl), False, True) if wl is not None and pod_spec(wl) else None

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {"workload": [list_to_key(params["workload"])]}
