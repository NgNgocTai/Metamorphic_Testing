"""Short advisor demo: MR-02 on the K1 seed with the REAL Kubescape (about 30-40 s).

C1 (valid RoleBinding -> local Role)  --MR-02-->  C2 (+ unbound same-name Role in another namespace)
then the same scanner on both, the controls C-0267/C-0272 before/after, expected vs actual relation, triage state.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import load_bundle  # noqa: E402
from k8s_mr_lab.registry import PolicyMapping, load_catalog  # noqa: E402
from k8s_mr_lab.runner import Runner  # noqa: E402
from k8s_mr_lab.scanners import load_scanner_config, make_scanner  # noqa: E402

BAR = "=" * 78


def step(n, title):
    print(f"\n{BAR}\n[{n}] {title}\n{BAR}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", default="kubescape", choices=["kubescape", "trivy"])
    ap.add_argument("--profile", default="wildcard_admin", choices=["secrets_read", "wildcard_admin"])
    ap.add_argument("--mr", default="MR-02", choices=["MR-02", "MR-05"], help="MR-05 + --scanner trivy is the secondary demo")
    ap.add_argument("--out", default=str(ROOT / "runs" / "demo_mr02"))
    a = ap.parse_args()

    cfg, mapping, catalog = load_scanner_config(ROOT / "config/scanners.yaml"), PolicyMapping.load(ROOT / "config/policy-mapping.yaml"), load_catalog(ROOT / "mrs/catalog.yaml")
    sc = make_scanner(a.scanner, cfg)
    seed_id = "K1-role-namespace" if a.mr == "MR-02" else "rbac-secrets-reader"
    seed = load_bundle(ROOT / ("seeds/historical/K1-role-namespace" if a.mr == "MR-02" else "seeds/synthetic/rbac-secrets-reader"), seed_id)
    mr = catalog[a.mr]
    params = next(p for p in mr.generate_parameters(seed, 9) if a.mr != "MR-02" or p["profile"] == a.profile)
    out = Path(a.out)
    shutil.rmtree(out, ignore_errors=True)

    step(1, f"Scanner pin: {a.scanner} {sc.version()} ({sc.mode}), policy {sc.policy_digest()[:16]}")
    step(2, "Source C1 (key objects)")
    if a.mr == "MR-02":
        print("MR-02 precondition: a RoleBinding points at a Role in its OWN namespace, with an existing ServiceAccount subject.")
        rb, role = seed.find("RoleBinding", "lab-a", "app-binding"), seed.find("Role", "lab-a", "app-role")
        print(f"RoleBinding lab-a/app-binding -> roleRef Role/{rb['roleRef']['name']}   subject SA lab-a/{rb['subjects'][0]['name']}")
        print(f"Role lab-a/app-role rules: {role['rules']}")
        print("Deployment lab-a/web uses serviceAccountName: app")
    else:
        print("MR-05 precondition: the Role's ONLY rule reads core-group Secrets (no other rule can grant the same permission).")
        print(f"Role lab-c/reader-role rules: {seed.find('Role', 'lab-c', 'reader-role')['rules']}")

    runner = Runner(sc, mapping, catalog, out / "run1", use_cache=False)
    r = runner.run_pair(seed_id, seed, mr, params, case_id="demo")

    step(3, f"{a.mr} transformation  C2 = T(C1)   (diff.patch)")
    print((Path(r.case_dir) / "diff.patch").read_text(encoding="utf-8"))
    print(f"structural pair check: {r.pair_status}")
    if a.mr == "MR-02":
        print("Kubernetes semantics: a RoleBinding resolves roleRef Role ONLY in its own namespace, so lab-a/app is NOT granted the decoy Role.")
    else:
        print("Kubernetes semantics: Secrets live in the core API group; a rule for resource 'secrets' in group 'apps' grants nothing.")

    step(4, f"Same scanner on C1 and C2 -> verdicts on the target resource  (relation: {mr.relation})")
    if not r.assessment:
        print(f"no assessment: {r.result} {r.reason}")
        return 1
    print(f"{'control':8} {'resource':32} {'C1':6} {'C2':6} outcome")
    for k in r.assessment.key_results:
        if (k.control in ("C-0267", "C-0272") if a.mr == "MR-02" else k.control in ("KSV-0113", "C-0015", "C-0267")):
            print(f"{k.control:8} {k.resource[1] + '/' + k.resource[2] + '/' + k.resource[3]:32} {k.source:6} {k.followup:6} {k.outcome}")

    step(5, "Expected relation vs actual")
    print("expected: the workload's verdict must NOT change (the decoy Role is not bound to its ServiceAccount)" if a.mr == "MR-02"
          else "expected: a control that detects core-Secrets read access must go FAIL -> PASS (the permission no longer exists)")
    bad = [k for k in r.assessment.key_results if k.outcome == "violation"]
    print(f"actual  : {len(bad)} comparison(s) violate the relation: {[(k.control, k.source + '->' + k.followup) for k in bad]}")
    print(f"RESULT  : {r.result}   ({r.reason})")

    step(6, "Triage state (rerun with fresh scans, no cache)")
    runner2 = Runner(sc, mapping, catalog, out / "run2", use_cache=False)
    r2 = runner2.run_pair(seed_id, seed, mr, params, case_id="demo")
    same = r2.result == r.result and {(k.control, k.resource) for k in r2.assessment.key_results if k.outcome == "violation"} == {(k.control, k.resource) for k in bad}
    print(f"reproduced on rerun: {same}  ->  status: {'CANDIDATE_REPRODUCED' if same and bad else 'NOT_REPRODUCED / no violation'}")
    print("This is an MR violation (an alert), NOT a confirmed defect. See docs/DEFECT_TRIAGE_RESULTS.md.")
    print(f"artifacts: {r.case_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
