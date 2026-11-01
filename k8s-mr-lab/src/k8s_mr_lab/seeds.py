"""Seed inventory, coverage model, deterministic selection and development/evaluation split. No scanner, no randomness.

A seed is worth what it lets an MR do, not how many YAML files it is. Each seed gets a set of FEATURE TOKENS (`dimension:value`)
drawn from a fixed vocabulary (VOCAB). Coverage of a dimension = covered tokens / vocabulary tokens of that dimension; the
vocabulary is declared here, before looking at any corpus, so a corpus cannot choose its own denominator.
`link:complete_chain` marks a bundle where a workload runs as a ServiceAccount that a binding grants a Role present in the bundle,
which is what subject-level MRs need and what a lone Pod or a lone Role cannot offer.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .bundles import BundleError, ConfigBundle, load_bundle, obj_key
from .k8s import WORKLOAD_KINDS, iter_containers, pod_spec, sa_subjects
from .validation import validate_source

VOCAB: dict[str, list[str]] = {
    "workload": list(WORKLOAD_KINDS),
    "rbac_kind": ["Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"],
    "subject_kind": ["ServiceAccount", "User", "Group"],
    "roleref_kind": ["Role", "ClusterRole"],
    "rule_api_group": ["core", "apps", "rbac.authorization.k8s.io", "wildcard", "other"],
    "rule_verb": ["get", "list", "watch", "create", "update", "patch", "delete", "wildcard"],
    "rule_resource": ["secrets", "pods", "configmaps", "rbac", "wildcard", "other"],
    "container_list": ["containers", "initContainers", "ephemeralContainers"],
    "security_context": ["privileged_true", "privileged_false", "host_network_true", "host_network_false", "host_pid_true",
                         "run_as_non_root_true", "read_only_root_fs_true"],
    "sa_token": ["automount_true", "automount_false"],
    "link": ["complete_chain", "binding_without_sa_object", "cross_namespace_subject", "multi_namespace"],
}
ALL_TOKENS = [f"{d}:{v}" for d, vs in VOCAB.items() for v in vs]
_RBAC = "rbac.authorization.k8s.io"


def _token_group(g: str) -> str:
    return "core" if g == "" else g if g in ("apps", _RBAC) else "wildcard" if g == "*" else "other"


def _resource_token(r: str) -> str:
    return r if r in ("secrets", "pods", "configmaps") else "wildcard" if r == "*" else "rbac" if r in ("roles", "rolebindings", "clusterroles", "clusterrolebindings") else "other"


def features(b: ConfigBundle) -> set[str]:
    t: set[str] = set()
    namespaces = {obj_key(o)[2] for o in b.objects if obj_key(o)[2]}
    if len(namespaces) >= 2:
        t.add("link:multi_namespace")
    for o in b.objects:
        kind = o.get("kind")
        if kind in WORKLOAD_KINDS:
            t.add(f"workload:{kind}")
        if kind in VOCAB["rbac_kind"]:
            t.add(f"rbac_kind:{kind}")
        ps = pod_spec(o)
        if ps:
            spec = ps[1]
            for lst in VOCAB["container_list"]:
                if spec.get(lst):
                    t.add(f"container_list:{lst}")
                for c in spec.get(lst) or []:
                    sc = c.get("securityContext") or {}
                    if "privileged" in sc:
                        t.add(f"security_context:privileged_{'true' if sc['privileged'] else 'false'}")
                    if sc.get("runAsNonRoot") is True:
                        t.add("security_context:run_as_non_root_true")
                    if sc.get("readOnlyRootFilesystem") is True:
                        t.add("security_context:read_only_root_fs_true")
            if "hostNetwork" in spec:
                t.add(f"security_context:host_network_{'true' if spec['hostNetwork'] else 'false'}")
            if spec.get("hostPID") is True:
                t.add("security_context:host_pid_true")
            if "automountServiceAccountToken" in spec:
                t.add(f"sa_token:automount_{'true' if spec['automountServiceAccountToken'] else 'false'}")
        if kind == "ServiceAccount" and "automountServiceAccountToken" in o:
            t.add(f"sa_token:automount_{'true' if o['automountServiceAccountToken'] else 'false'}")
        if kind in ("Role", "ClusterRole"):
            for rule in o.get("rules") or []:
                for g in rule.get("apiGroups") or []:
                    t.add(f"rule_api_group:{_token_group(g)}")
                for v in rule.get("verbs") or []:
                    if v == "*" or v in VOCAB["rule_verb"]:
                        t.add(f"rule_verb:{'wildcard' if v == '*' else v}")
                for r in rule.get("resources") or []:
                    t.add(f"rule_resource:{_resource_token(r)}")
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            ref = o.get("roleRef") or {}
            if ref.get("kind") in VOCAB["roleref_kind"]:
                t.add(f"roleref_kind:{ref['kind']}")
            for s in o.get("subjects") or []:
                if s.get("kind") in VOCAB["subject_kind"]:
                    t.add(f"subject_kind:{s['kind']}")
            for ns, name in sa_subjects(o):
                if ns != obj_key(o)[2]:
                    t.add("link:cross_namespace_subject")
                if not b.find("ServiceAccount", ns, name):
                    t.add("link:binding_without_sa_object")
                    continue
                role_ok = (ref.get("kind") == "Role" and b.find("Role", obj_key(o)[2], ref.get("name", ""))) or \
                          (ref.get("kind") == "ClusterRole" and b.find("ClusterRole", "", ref.get("name", "")))
                if role_ok and any((p := pod_spec(w)) and obj_key(w)[2] == ns and (p[1].get("serviceAccountName") or "default") == name for w in b.objects):
                    t.add("link:complete_chain")
    return t


@dataclass
class SeedRecord:
    seed_id: str
    root: str
    path: str
    semantic_digest: str = ""
    valid: bool = False
    problems: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    n_objects: int = 0
    partition: str = ""
    duplicate_of: str = ""

    def to_json(self) -> dict:
        return {k: getattr(self, k) for k in ("seed_id", "root", "path", "semantic_digest", "valid", "problems", "tokens", "n_objects",
                                              "partition", "duplicate_of")}


def _candidates(root: Path) -> list[Path]:
    if any(root.glob("*.yaml")) or any(root.glob("*.yml")):
        return sorted(p for p in list(root.glob("*.yaml")) + list(root.glob("*.yml")) if not p.name.startswith("_"))
    return sorted(d for d in root.iterdir() if d.is_dir() and (any(d.glob("*.yaml")) or any(d.glob("*.yml"))))


def inventory(roots: list[str], partitions: dict[str, str] | None = None) -> list[SeedRecord]:
    """Deterministic: sorted paths, content digests; the first seed with a given digest owns it, later ones are marked duplicates."""
    out: list[SeedRecord] = []
    seen: dict[str, str] = {}
    for root in map(Path, roots):
        for p in _candidates(root):
            rec = SeedRecord(seed_id=p.stem if p.is_file() else p.name, root=root.name, path=p.as_posix(),
                             partition=(partitions or {}).get(root.name, "UNASSIGNED"))
            try:
                b = load_bundle(p, rec.seed_id)
            except BundleError as e:
                rec.problems = [f"load_error: {e}"]
                out.append(rec)
                continue
            rec.n_objects = len(b.objects)
            rec.semantic_digest = b.semantic_digest()
            rec.problems = validate_source(b)
            rec.valid = not rec.problems
            rec.tokens = sorted(features(b))
            if rec.semantic_digest in seen:
                rec.duplicate_of = seen[rec.semantic_digest]
            else:
                seen[rec.semantic_digest] = f"{rec.root}/{rec.seed_id}"
            out.append(rec)
    return out


def usable(records: list[SeedRecord]) -> list[SeedRecord]:
    return [r for r in records if r.valid and not r.duplicate_of]


def coverage(records: list[SeedRecord]) -> dict:
    """Per-dimension covered/defined over the USABLE (valid, non-duplicate) seeds."""
    have = {t for r in usable(records) for t in r.tokens}
    dims = {}
    for d, vs in VOCAB.items():
        cov = [v for v in vs if f"{d}:{v}" in have]
        dims[d] = {"covered": len(cov), "defined": len(vs), "missing": [v for v in vs if v not in cov]}
    return {"dimensions": dims, "covered_tokens": sum(x["covered"] for x in dims.values()), "defined_tokens": len(ALL_TOKENS),
            "seeds": {"total": len(records), "valid": sum(r.valid for r in records), "duplicates": sum(bool(r.duplicate_of) for r in records),
                      "usable": len(usable(records)), "invalid_or_unloadable": sum(not r.valid for r in records)}}


def mr_applicability(records: list[SeedRecord], catalog: dict) -> dict[str, dict]:
    """How many usable seeds each MR applies to, and how many it generates cases on (static; no scanner)."""
    res = {}
    for mr_id, mr in catalog.items():
        n = cases = 0
        for r in usable(records):
            b = load_bundle(r.path, r.seed_id)
            ok, _ = mr.applicable(b)
            if ok:
                n += 1
                cases += len(mr.generate_parameters(b, 50))
        res[mr_id] = {"applicable_seeds": n, "usable_seeds": len(usable(records)), "cases": cases}
    return res


def select(records: list[SeedRecord], k: int) -> list[SeedRecord]:
    """Greedy set cover over feature tokens; ties go to the smaller (root, seed_id). Deterministic, no randomness."""
    pool = sorted(usable(records), key=lambda r: (r.root, r.seed_id))
    chosen: list[SeedRecord] = []
    covered: set[str] = set()
    while pool and len(chosen) < k:
        best = max(pool, key=lambda r: (len(set(r.tokens) - covered), -pool.index(r)))
        if not set(best.tokens) - covered:
            break
        chosen.append(best)
        covered |= set(best.tokens)
        pool.remove(best)
    return chosen


def split(records: list[SeedRecord], evaluation_percent: int = 30, salt: str = "k8s-mr-lab-split-v1") -> dict[str, str]:
    """seed key -> development | evaluation. Seeds of partitions DEV/REGRESSION are always development (they shaped the MRs).
    Others are assigned by sha256(salt + semantic digest), so a split is reproducible and independent of file order."""
    out = {}
    for r in usable(records):
        key = f"{r.root}/{r.seed_id}"
        if r.partition in ("DEV", "REGRESSION"):
            out[key] = "development"
        else:
            bucket = int(hashlib.sha256((salt + r.semantic_digest).encode()).hexdigest(), 16) % 100
            out[key] = "evaluation" if bucket < evaluation_percent else "development"
    return out
