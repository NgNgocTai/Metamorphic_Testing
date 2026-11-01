"""Generate config/control-registry.yaml: the ONE place that says what each mapped scanner control reads and reports on.

    python scripts/derive_control_registry.py --trivy-policies <dir of *.rego> --kubescape-artifacts <dir> --out config/control-registry.yaml

The set of controls is whatever config/policy-mapping.yaml maps. Everything here is read from the PINNED policy artifacts; nothing is
hand-written, so the file is regenerated, never edited. Fields per control:

  title          policy title
  source         artifact file name, and source_sha256 its digest (drift detector)
  scope          judged_object  (Trivy) the check sees only the document it judges
                 all_matched_kinds (Kubescape) every kind in the rule's `match` is loaded into the rego input and may be joined
  reads          kinds the control can observe (Trivy: the judged kinds; Kubescape: `match`)
  reports_on     kinds a verdict of this control can be attached to by our normalizer:
                   Trivy: the judged kinds
                   Kubescape, aggregator rule (rego iterates `subjectVector`, i.e. subject-role-rolebinding triples): `match` plus
                       ServiceAccount, Role, ClusterRole, RoleBinding, ClusterRoleBinding (normalize/kubescape.py attaches the
                       verdict to every member of the triple)
                   Kubescape, other: the workload kinds of `match` when it has any, else `match`
  reports_on_rule  names the rule above that was applied
  scope_rule       (aggregators) `rbac_triple_member`: of the aggregated kinds only members of a binding chain are judged (checker.SCOPE_RULES)
It also records the policy digest the registry was derived under (`derived_under`); a run on different artifacts is flagged in its lock.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

WORKLOAD = ["CronJob", "DaemonSet", "Deployment", "Job", "Pod", "ReplicaSet", "ReplicationController", "StatefulSet", "DeploymentConfig"]
CANON = {k.lower(): k for k in (*WORKLOAD, "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount", "Namespace",
                                "ConfigMap", "Service", "Secret", "NetworkPolicy")}
AGGREGATED = ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "ServiceAccount"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def trivy_find(policies: Path, control: str) -> Path:
    for f in sorted(policies.glob("*.rego")):
        if re.search(rf"#\s+id:\s*{re.escape(control)}\s*$", f.read_text(encoding="utf-8"), re.M):
            return f
    raise SystemExit(f"Trivy check {control} not found in {policies}")


def trivy_entry(policies: Path, control: str) -> dict:
    f = trivy_find(policies, control)
    lines = f.read_text(encoding="utf-8").splitlines()
    kinds: list[str] = []
    for i, line in enumerate(lines):
        if re.match(r"#\s+subtypes:\s*$", line):
            for nxt in lines[i + 1:]:
                m = re.match(r"#\s+-\s+kind:\s*(\w+)", nxt)
                if not m:
                    break
                kinds.append(CANON.get(m.group(1).lower(), m.group(1)))
            break
    title = (re.search(r'#\s+title:\s*"?(.+?)"?\s*$', "\n".join(lines), re.M) or [None, ""])[1]
    kinds = sorted(set(kinds))
    if not kinds:
        raise SystemExit(f"{control}: no selector subtypes parsed from {f.name}")
    return {"title": title, "source": f.name, "source_sha256": sha(f), "scope": "judged_object", "reads": kinds,
            "reports_on": kinds, "reports_on_rule": "trivy_selector_subtypes"}


def kubescape_entry(artifacts: Path, control: str) -> dict:
    f = artifacts / f"{control.lower()}.json"
    d = json.loads(f.read_text(encoding="utf-8"))
    match = sorted({k for r in d["rules"] for m in r.get("match", []) for k in m.get("resources", [])})
    aggregator = any("subjectVector" in r.get("rule", "") for r in d["rules"])
    if aggregator:
        reports, rule = sorted(set(match) | set(AGGREGATED)), "aggregator_subject_role_rolebinding"
    else:
        wl = [k for k in match if k in WORKLOAD]
        reports, rule = (wl, "workload_kinds_of_match") if wl else (match, "match")
    entry = {"title": d["name"], "source": f.name, "source_sha256": sha(f), "scope": "all_matched_kinds", "aggregator": aggregator,
             "reads": match, "reports_on": reports, "reports_on_rule": rule}
    if aggregator:       # an aggregator judges subject-role-rolebinding chains: an unbound Role/ServiceAccount is outside its scope
        entry["scope_rule"] = "rbac_triple_member"
    return entry


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mapping", default="config/policy-mapping.yaml")
    ap.add_argument("--trivy-policies", required=True)
    ap.add_argument("--kubescape-artifacts", required=True)
    ap.add_argument("--trivy-policy-digest", required=True, help="digest of the Trivy checks bundle (what `k8s-mr-lab versions` prints)")
    ap.add_argument("--kubescape-policy-digest", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    mapping = yaml.safe_load(Path(a.mapping).read_text(encoding="utf-8"))
    used: dict[str, set[str]] = {"trivy": set(), "kubescape": set()}
    for per_scanner in mapping["mrs"].values():
        for scanner, entries in (per_scanner or {}).items():
            if scanner in used:
                used[scanner] |= {e["control"] for e in entries or []}
    out = {"version": 1, "derived_under": {"trivy": a.trivy_policy_digest, "kubescape": a.kubescape_policy_digest},
           "controls": {"trivy": {c: trivy_entry(Path(a.trivy_policies), c) for c in sorted(used["trivy"])},
                        "kubescape": {c: kubescape_entry(Path(a.kubescape_artifacts), c) for c in sorted(used["kubescape"])}}}
    header = ("# GENERATED by scripts/derive_control_registry.py from the pinned policy artifacts. Do not edit by hand; regenerate.\n"
              "# Single source for what each control reads and what it reports on (see that script's docstring).\n")
    Path(a.out).write_text(header + yaml.safe_dump(out, sort_keys=True), encoding="utf-8")
    print(f"wrote {a.out}: {sum(len(v) for v in out['controls'].values())} controls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
