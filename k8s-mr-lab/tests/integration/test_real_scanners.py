"""Integration tests against the REAL Trivy / Kubescape binaries. Skipped (never faked) when a binary is missing
or is not the pinned version. These are the only tests whose outputs may be cited as research evidence."""
import json
import shutil
from pathlib import Path

import pytest

from conftest import ROOT, SEEDS
from k8s_mr_lab.bundles import load_bundle
from k8s_mr_lab.registry import PolicyMapping, load_catalog
from k8s_mr_lab.runner import Runner
from k8s_mr_lab.scanners import load_scanner_config, make_scanner

pytestmark = pytest.mark.integration
CFG = load_scanner_config(ROOT / "config" / "scanners.yaml")


def real(name):
    if shutil.which(CFG[name]["binary"]) is None:
        pytest.skip(f"{name} binary not installed")
    sc = make_scanner(name, CFG)
    if sc.version() != str(CFG[name]["version"]):
        pytest.skip(f"{name} version {sc.version()} != pinned {CFG[name]['version']}")
    return sc


@pytest.fixture()
def runner_for(tmp_path):
    mapping, catalog = PolicyMapping.load(ROOT / "config/policy-mapping.yaml"), load_catalog(ROOT / "mrs/catalog.yaml")
    return lambda name: Runner(real(name), mapping, catalog, tmp_path / name)


def test_int01_trivy_real_run_stores_raw_json_version_mode(tmp_path):
    sc = real("trivy")
    bundle = load_bundle(SEEDS / "rbac-basic", "rbac-basic")
    path, _ = bundle.write(tmp_path / "in")
    inv = sc.execute(path.parent, tmp_path / "r.json")
    assert inv.ok, inv.error
    raw = json.loads((tmp_path / "r.json").read_text())
    assert raw["Results"][0]["Misconfigurations"], "expected check results (PASS included)"
    assert (inv.version, inv.mode) == ("0.75.0", "local-file") and inv.policy_digest.startswith("sha256:")
    assert inv.exit_code == 0 and "--skip-check-update" in inv.command


def test_int02_kubescape_real_run_stores_raw_json_version_mode(tmp_path):
    sc = real("kubescape")
    bundle = load_bundle(SEEDS / "rbac-workload", "rbac-workload")
    path, _ = bundle.write(tmp_path / "in")
    inv = sc.execute(path.parent, tmp_path / "r.json")
    assert inv.ok, inv.error
    raw = json.loads((tmp_path / "r.json").read_text())
    assert raw["results"] and (inv.version, inv.mode) == ("v4.0.15", "local-file") and len(inv.policy_digest) == 64


def test_int03_historical_k1_is_reported_honestly(runner_for):
    """K1 on the pinned Kubescape: either reproduced (VIOLATION on C-0267/C-0272) or honestly not reproduced (PASS)."""
    runner = runner_for("kubescape")
    res = runner.run_seed(ROOT / "seeds/historical/K1-role-namespace", ["MR-02"])
    assert res and all(r.result in ("VIOLATION", "PASS") for r in res), [(r.result, r.reason) for r in res]
    for r in res:
        d = Path(r.case_dir)
        assert (d / "scanner-source.json").exists() and (d / "scanner-followup.json").exists()
    flipped = {k.control for r in res if r.assessment for k in r.assessment.key_results if k.outcome == "violation"}
    print("K1 reproduced controls:", sorted(flipped) or "none (not reproduced on this version)")
