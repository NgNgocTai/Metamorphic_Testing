"""Kubescape JSON report -> NormalizedReport.

Facts verified on the pinned version (tests/golden):
  * `results[].controls[]` carries an explicit passed/failed/skipped status per control, and a control is listed on a
    resource only when it is relevant to it, so presence is coverage evidence;
  * RBAC results are aggregated per (subject, Role, RoleBinding) triple (checked with a two-subject, two-Role real report in
    tests/golden/*rbac-multi-subject*): one resourceID concatenates ServiceAccount/Role/RoleBinding, e.g.
    '/lab-a/ServiceAccount/app/path=1/api=rbac.authorization.k8s.io/v1/lab-a/Role/app-role/path=2/...'. Every member
    object receives the verdict; worst status wins when an object appears in several results.
"""
from __future__ import annotations

import re

from ..bundles import ConfigBundle, obj_key
from ..model import FAIL, NOT_EVALUATED, PASS, NormalizedReport, ResKey

KINDS = ("ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|Pod|Deployment|ReplicaSet|DaemonSet|"
         "StatefulSet|Job|CronJob|Namespace|ConfigMap|Service|Secret")
_MEMBER = re.compile(rf"/(?P<ns>[A-Za-z0-9.\-]+)/(?P<kind>{KINDS})/(?P<name>[A-Za-z0-9.\-_:]+)")
_VERSION = re.compile(r"^v\d+((alpha|beta)\d+)?$")
_RANK = {PASS: 0, NOT_EVALUATED: 1, FAIL: 2}


def members(resource_id: str, bundle: ConfigBundle) -> list[ResKey]:
    out: list[ResKey] = []
    for m in _MEMBER.finditer("/" + resource_id.lstrip("/")):
        ns = "" if _VERSION.match(m["ns"]) else m["ns"]
        obj = bundle.find(m["kind"], ns, m["name"])
        if obj is not None and obj_key(obj) not in out:
            out.append(obj_key(obj))
    return out


def _status(control: dict) -> str:
    s = (control.get("status") or {}).get("status")
    return PASS if s == "passed" else FAIL if s == "failed" else NOT_EVALUATED


def normalize(raw: dict, bundle: ConfigBundle) -> NormalizedReport:
    rep = NormalizedReport("kubescape")
    for result in raw.get("results") or []:
        mem = members(result.get("resourceID", ""), bundle)
        if not mem:
            rep.notes.append(f"result for unknown object skipped: {result.get('resourceID', '')[-80:]}")
            continue
        for c in result.get("controls") or []:
            cid, st = c.get("controlID", ""), _status(c)
            for key in mem:
                prev = rep.verdicts.get((cid, key))
                if prev is None or _RANK[st] > _RANK[prev.status]:
                    rep.add(cid, key, st, f"resourceID=...{result['resourceID'][-48:]}", f"rules={[r.get('name') for r in c.get('rules') or []]}")
    return rep
