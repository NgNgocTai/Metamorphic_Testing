"""Ablation probes that isolate the cause of the two defect candidates, using the REAL pinned scanners.

Each variant changes ONE thing relative to the candidate so the trigger can be attributed. Output:
docs/evidence/k1_kubescape_ablation.json and docs/evidence/n2_trivy_ablation.json (raw control excerpts included).
Run: python scripts/triage_probe.py   (inside the environment with the binaries)
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import ConfigBundle, load_bundle  # noqa: E402
from k8s_mr_lab.normalize import normalize  # noqa: E402
from k8s_mr_lab.registry import PolicyMapping  # noqa: E402
from k8s_mr_lab.scanners import load_scanner_config, make_scanner  # noqa: E402

CFG = load_scanner_config(ROOT / "config/scanners.yaml")
MAP = PolicyMapping.load(ROOT / "config/policy-mapping.yaml")
OUT = ROOT / "docs" / "evidence"
RBAC = "rbac.authorization.k8s.io/v1"


def scan(name: str, bundle: ConfigBundle):
    sc = make_scanner(name, CFG)
    with tempfile.TemporaryDirectory() as td:
        path, spans = bundle.write(Path(td) / "in")
        inv = sc.execute(path.parent, Path(td) / "r.json")
        if not inv.ok:
            raise SystemExit(f"{name}: {inv.error}")
        raw = json.loads((Path(td) / "r.json").read_text())
    return raw, normalize(name, raw, bundle, spans, MAP.control_kinds(name)), inv


def role(ns, name, rules):
    return {"apiVersion": RBAC, "kind": "Role", "metadata": {"name": name, "namespace": ns}, "rules": rules}


SECRETS = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]
CONFIGMAPS = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]


def k1() -> dict:
    seed = load_bundle(ROOT / "seeds/synthetic/rbac-workload", "rbac-workload")
    web = ("apps", "Deployment", "lab-a", "web")
    variants: dict[str, ConfigBundle] = {}
    variants["A_baseline_no_decoy"] = seed
    b = seed.clone(); b.objects.append(role("lab-a-decoy", "app-role", SECRETS)); variants["B_candidate_decoy_same_name_secrets"] = b
    b = seed.clone(); b.objects.append(role("lab-a-decoy", "app-role", CONFIGMAPS)); variants["C_decoy_same_name_benign_rules"] = b
    b = seed.clone(); b.objects.append(role("lab-a-decoy", "other-role", SECRETS)); variants["D_decoy_DIFFERENT_name_secrets"] = b
    b = seed.clone(); b.objects.append(role("lab-a", "unrelated", SECRETS)); variants["E_unbound_secrets_role_SAME_namespace_different_name"] = b
    b = seed.clone(); b.find("Role", "lab-a", "app-role")["rules"] = copy.deepcopy(SECRETS); variants["F_positive_control_local_role_really_grants_secrets"] = b
    res = {}
    for name, bundle in variants.items():
        raw, rep, inv = scan("kubescape", bundle)
        res[name] = {"C-0267": rep.get("C-0267", web).status, "C-0272": rep.get("C-0272", web).status,
                     "C-0015(role app-role)": rep.get("C-0015", ("rbac.authorization.k8s.io", "Role", "lab-a", "app-role")).status,
                     "raw_workload_controls": [c for r in raw.get("results", []) if r["resourceID"].endswith("Deployment/web")
                                               for c in r["controls"] if c["controlID"] in ("C-0267", "C-0272")]}
    return {"scanner": "kubescape", "version": inv.version, "policy_digest": inv.policy_digest, "target": "Deployment lab-a/web",
            "note": "each variant differs from the baseline in exactly one respect; the scanned Role/RoleBinding/SA of lab-a never change except in F",
            "variants": res}


def n2() -> dict:
    seed = load_bundle(ROOT / "seeds/synthetic/rbac-secrets-reader", "rbac-secrets-reader")
    target = ("rbac.authorization.k8s.io", "Role", "lab-c", "reader-role")
    variants: dict[str, ConfigBundle] = {}

    def with_rules(rules):
        b = seed.clone(); b.find("Role", "lab-c", "reader-role")["rules"] = rules; return b
    base = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}]
    variants["A_source_core_group_secrets"] = with_rules(base)
    variants["B_candidate_apiGroup_apps_secrets"] = with_rules([{**base[0], "apiGroups": ["apps"]}])
    variants["C_apiGroup_nonexistent_secrets"] = with_rules([{**base[0], "apiGroups": ["no-such-group.example.com"]}])
    variants["D_apiGroup_apps_deployments_get(no secrets)"] = with_rules([{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get"]}])
    res = {}
    for name, bundle in variants.items():
        roles = bundle.find("Role", "lab-c", "reader-role")
        assert len(roles["rules"]) == 1, "only one rule may grant anything"
        raw, rep, inv = scan("trivy", bundle)
        fails = [m for r in raw["Results"] for m in r["Misconfigurations"] if m["ID"] == "KSV-0113" and m["Status"] == "FAIL"]
        for m in fails:
            (m.get("CauseMetadata") or {}).pop("Code", None)
        _, ksrep, kinv = scan("kubescape", bundle)
        res[name] = {"trivy_KSV-0113": rep.get("KSV-0113", target).status, "trivy_raw_fail_entries": fails,
                     "kubescape_C-0015": ksrep.get("C-0015", target).status}
    return {"scanner": "trivy (+ kubescape for contrast)", "version": inv.version, "kubescape_version": kinv.version,
            "policy_digest": inv.policy_digest, "target": "Role lab-c/reader-role",
            "note": "the Role has exactly one rule in every variant, so no other rule/binding can grant the same permission",
            "variants": res}


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "k1_kubescape_ablation.json").write_text(json.dumps(k1(), indent=2), encoding="utf-8")
    (OUT / "n2_trivy_ablation.json").write_text(json.dumps(n2(), indent=2), encoding="utf-8")
    for f in ("k1_kubescape_ablation.json", "n2_trivy_ablation.json"):
        d = json.loads((OUT / f).read_text())
        print(f, d["version"])
        for k, v in d["variants"].items():
            print("  ", k, {a: b for a, b in v.items() if not a.startswith(("raw", "trivy_raw"))})
