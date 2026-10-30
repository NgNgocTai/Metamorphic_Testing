"""Small Kubernetes-domain helpers used by MR preconditions (no scanner knowledge here)."""
from __future__ import annotations

from typing import Iterator

from .bundles import ConfigBundle, obj_key
from .model import ResKey

RBAC = "rbac.authorization.k8s.io"
WORKLOAD_KINDS = ("Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob")
READ_VERBS = {"get", "list", "watch"}


def pod_spec(obj: dict) -> tuple[list[str], dict] | None:
    """Return (path-to-podspec, podspec) for workload kinds, else None."""
    kind = obj.get("kind")
    if kind == "Pod":
        path = ["spec"]
    elif kind in ("Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"):
        path = ["spec", "template", "spec"]
    elif kind == "CronJob":
        path = ["spec", "jobTemplate", "spec", "template", "spec"]
    else:
        return None
    cur = obj
    for p in path:
        cur = (cur or {}).get(p)
        if not isinstance(cur, dict):
            return None
    return path, cur


def iter_containers(obj: dict) -> Iterator[tuple[str, int, dict]]:
    """Yield (list-name, index, container) for regular containers only."""
    ps = pod_spec(obj)
    if not ps:
        return
    for i, c in enumerate(ps[1].get("containers") or []):
        yield "containers", i, c


def local_role_bindings(bundle: ConfigBundle) -> list[dict]:
    """RoleBindings that point at a Role in their own namespace and have a ServiceAccount subject."""
    out = []
    for rb in bundle.of_kind("RoleBinding"):
        ref = rb.get("roleRef") or {}
        ns = obj_key(rb)[2]
        if ref.get("kind") != "Role" or not bundle.find("Role", ns, ref.get("name", "")):
            continue
        if any(s.get("kind") == "ServiceAccount" for s in rb.get("subjects") or []):
            out.append(rb)
    return out


def sa_subjects(rb: dict) -> list[tuple[str, str]]:
    ns = obj_key(rb)[2]
    return [(s.get("namespace") or ns, s["name"]) for s in rb.get("subjects") or []
            if s.get("kind") == "ServiceAccount" and s.get("name")]


def sa_key(ns: str, name: str) -> ResKey:
    return ("", "ServiceAccount", ns, name)


def workloads_using_sa(bundle: ConfigBundle, ns: str, sa_name: str) -> list[ResKey]:
    out = []
    for o in bundle.objects:
        ps = pod_spec(o)
        if not ps or obj_key(o)[2] != ns:
            continue
        name = ps[1].get("serviceAccountName") or ps[1].get("serviceAccount") or "default"
        if name == sa_name:
            out.append(obj_key(o))
    return out


def bound_service_accounts(bundle: ConfigBundle, role: dict) -> list[ResKey]:
    """ServiceAccount objects present in the bundle that are bound to `role` (namespace-correct resolution)."""
    kind, (_, _, rns, rname) = role.get("kind"), obj_key(role)
    out: list[ResKey] = []
    for b in bundle.of_kind("RoleBinding", "ClusterRoleBinding"):
        ref = b.get("roleRef") or {}
        bns = obj_key(b)[2]
        if ref.get("kind") != kind or ref.get("name") != rname:
            continue
        if kind == "Role" and (b.get("kind") != "RoleBinding" or bns != rns):
            continue
        for ns, name in sa_subjects(b):
            if bundle.find("ServiceAccount", ns, name) and sa_key(ns, name) not in out:
                out.append(sa_key(ns, name))
    return out


def permission_tuples(role: dict) -> set[tuple]:
    """Expanded (apiGroup, resource, resourceName, nonResourceURL, verb) tuples granted by a Role/ClusterRole."""
    out: set[tuple] = set()
    for rule in role.get("rules") or []:
        groups = rule.get("apiGroups") or [None]
        resources = rule.get("resources") or [None]
        names = rule.get("resourceNames") or [None]
        urls = rule.get("nonResourceURLs") or [None]
        for g in groups:
            for r in resources:
                for n in names:
                    for u in urls:
                        for v in rule.get("verbs") or []:
                            out.add((g, r, n, u, v))
    return out
