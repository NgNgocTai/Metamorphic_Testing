"""Capture RAW reports from the real scanners for a fixed set of (seed, MR variant) inputs.

Output (tests/golden/): <scanner>__<name>.json (raw), <name>.bundle.yaml (exact scanned text), <name>.spans.json,
and meta.json (versions/digests/commands). Normalizer golden tests read these; they are never hand-edited.
Run inside the environment that has the binaries:  python scripts/capture_golden.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import load_bundle  # noqa: E402
from k8s_mr_lab.scanners import load_scanner_config, make_scanner  # noqa: E402
from k8s_mr_lab.transforms.pod_privileged import PrivilegedFlip  # noqa: E402
from k8s_mr_lab.transforms.rbac_api_group import ApiGroupSwitch  # noqa: E402
from k8s_mr_lab.transforms.rbac_decoy_role import DecoySameNameRole  # noqa: E402
from k8s_mr_lab.transforms.yaml_reorder import YamlKeyOrder  # noqa: E402

GOLDEN = ROOT / "tests" / "golden"


def variants():
    seeds = {p.name: load_bundle(p) for p in sorted((ROOT / "seeds" / "synthetic").iterdir()) if p.is_dir()}
    for name, b in seeds.items():
        yield f"{name}__source", b
    mr02 = DecoySameNameRole()
    for prof in ("secrets_read", "wildcard_admin"):
        src = seeds["rbac-workload"]
        p = [x for x in mr02.generate_parameters(src, 9) if x["profile"] == prof][0]
        yield f"rbac-workload__mr02-{prof}", mr02.transform(src, p)[0]
    mr05 = ApiGroupSwitch()
    src = seeds["rbac-secrets-reader"]
    yield "rbac-secrets-reader__mr05", mr05.transform(src, mr05.generate_parameters(src, 1)[0])[0]
    mr04 = PrivilegedFlip()
    for sname in ("pod-basic", "rbac-workload"):
        src = seeds[sname]
        yield f"{sname}__mr04", mr04.transform(src, mr04.generate_parameters(src, 1)[0])[0]
    mr01 = YamlKeyOrder()
    src = seeds["rbac-workload"]
    yield "rbac-workload__mr01-reverse", mr01.transform(src, {"mode": "reverse"})[0]
    yield "rbac-multi-subject__source", multi_subject_bundle()


def multi_subject_bundle():
    """Adversarial RBAC case for the normalizer: SA a has a benign Role AND a Secrets Role, SA b shares only the benign Role."""
    from k8s_mr_lab.bundles import ConfigBundle
    rbac = "rbac.authorization.k8s.io"

    def role(n, res):
        return {"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": n, "namespace": "lab-m"},
                "rules": [{"apiGroups": [""], "resources": [res], "verbs": ["get"]}]}

    def bind(n, r, s):
        return {"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": n, "namespace": "lab-m"},
                "subjects": [{"kind": "ServiceAccount", "name": s, "namespace": "lab-m"}],
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": r}}   # apiGroup has NO /v1; with /v1 Kubescape ignores the link

    def sa(n):
        return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": n, "namespace": "lab-m"}}

    def dep(n, s):
        return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": n, "namespace": "lab-m"},
                "spec": {"selector": {"matchLabels": {"a": n}}, "template": {"metadata": {"labels": {"a": n}},
                         "spec": {"serviceAccountName": s, "containers": [{"name": "c", "image": "nginx:1.27"}]}}}}
    return ConfigBundle([sa("a"), sa("b"), role("benign", "configmaps"), role("secretsrole", "secrets"),
                         bind("a-benign", "benign", "a"), bind("a-secrets", "secretsrole", "a"), bind("b-benign", "benign", "b"),
                         dep("wa", "a"), dep("wb", "b")], "", "rbac-multi-subject")


def main() -> int:
    cfg = load_scanner_config(ROOT / "config" / "scanners.yaml")
    GOLDEN.mkdir(parents=True, exist_ok=True)
    meta = {}
    for sname in ("trivy", "kubescape"):
        sc = make_scanner(sname, cfg)
        for name, bundle in variants():
            with tempfile.TemporaryDirectory() as td:
                path, spans = bundle.write(Path(td) / "in")
                out = Path(td) / "report.json"
                inv = sc.execute(path.parent, out)
                if not inv.ok:
                    print(f"[{sname}] {name}: {inv.error}", file=sys.stderr)
                    return 1
                (GOLDEN / f"{sname}__{name}.json").write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
            (GOLDEN / f"{name}.bundle.yaml").write_text(bundle.dump(), encoding="utf-8")
            (GOLDEN / f"{name}.spans.json").write_text(json.dumps(
                [[s.start, s.end, list(s.key)] for s in bundle.dump_with_spans()[1]]), encoding="utf-8")
            meta[sname] = {"version": inv.version, "mode": inv.mode, "policy_digest": inv.policy_digest,
                           "command_example": inv.command}
            print(f"[{sname}] {name}: ok ({inv.elapsed_ms} ms)")
    (GOLDEN / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
