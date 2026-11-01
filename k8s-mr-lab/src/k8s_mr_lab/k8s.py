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


def grants_core_secret_read(role: dict) -> bool:
    """True if any rule of the Role/ClusterRole can read core-group Secrets (wildcards included)."""
    for rule in role.get("rules") or []:
        if (set(rule.get("apiGroups") or []) & {"", "*"} and set(rule.get("resources") or []) & {"secrets", "*"}
                and set(rule.get("verbs") or []) & (READ_VERBS | {"*"})):
            return True
    return False


def secret_read_granted_elsewhere(bundle: ConfigBundle, role: dict, sas: list[ResKey]) -> bool:
    """Could a ServiceAccount in `sas` still read core Secrets after `role` stops granting it?

    Looks at every other RoleBinding/ClusterRoleBinding that names the SA (directly, as the equivalent User, or through
    the SA groups). Conservative: a referenced ClusterRole that is not in the bundle (e.g. built-in `edit`) counts as
    'yes', because we cannot show it grants nothing."""
    if not sas:
        return False
    ids = {(k[2], k[3]) for k in sas}
    users = {f"system:serviceaccount:{ns}:{n}" for ns, n in ids}
    groups = {"system:serviceaccounts", "system:authenticated"} | {f"system:serviceaccounts:{ns}" for ns, _ in ids}
    own = obj_key(role)
    for b in bundle.of_kind("RoleBinding", "ClusterRoleBinding"):
        bns = obj_key(b)[2]
        names_sa = any((s.get("kind") == "ServiceAccount" and ((s.get("namespace") or bns), s.get("name")) in ids)
                       or (s.get("kind") == "User" and s.get("name") in users)
                       or (s.get("kind") == "Group" and s.get("name") in groups)
                       for s in b.get("subjects") or [])
        if not names_sa:
            continue
        ref = b.get("roleRef") or {}
        target = (bundle.find("Role", bns, ref.get("name", "")) if ref.get("kind") == "Role"
                  else bundle.find("ClusterRole", "", ref.get("name", "")))
        if target is None:
            return True                      # cannot prove it grants nothing
        if obj_key(target) != own and grants_core_secret_read(target):
            return True
    return False


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


def workloads_of_service_accounts(bundle: ConfigBundle, sas: list[ResKey]) -> list[ResKey]:
    """Workloads that run as any of the given ServiceAccount keys."""
    return [w for (_, _, ns, name) in sas for w in workloads_using_sa(bundle, ns, name)]


def other_bindings_naming_sa(bundle: ConfigBundle, binding_key: ResKey, ns: str, name: str) -> list[ResKey]:
    """Bindings OTHER than `binding_key` that grant something to ServiceAccount ns:name: by ServiceAccount subject, by the equivalent
    User `system:serviceaccount:ns:name`, or through the groups every service account belongs to. Any hit means a role may reach the
    ServiceAccount by another path (so a one-binding change cannot be shown to remove it)."""
    user = f"system:serviceaccount:{ns}:{name}"
    groups = {"system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated"}
    out: list[ResKey] = []
    for b in bundle.of_kind("RoleBinding", "ClusterRoleBinding"):
        if obj_key(b) == binding_key:
            continue
        bns = obj_key(b)[2]
        for s in b.get("subjects") or []:
            hit = ((s.get("kind") == "ServiceAccount" and s.get("name") == name and (s.get("namespace") or bns) == ns)
                   or (s.get("kind") == "User" and s.get("name") == user)
                   or (s.get("kind") == "Group" and s.get("name") in groups))
            if hit and obj_key(b) not in out:
                out.append(obj_key(b))
    return out
