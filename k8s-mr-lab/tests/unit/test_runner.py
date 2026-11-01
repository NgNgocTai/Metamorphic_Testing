"""Runner tests. The scanner CLI is replaced by a *replay* of raw reports captured from the real binaries
(tests/golden). This tests the framework, it is NOT research evidence; research evidence comes from integration runs."""
import json
from pathlib import Path

import pytest

from k8s_mr_lab.runner import Runner
from k8s_mr_lab.scanners import make_scanner
from conftest import GOLDEN, ROOT, SEEDS

from k8s_mr_lab.bundles import load_bundle


class Replay:
    def __init__(self, scanner: str, version: str, on_scan=None, garbage: bool = False):
        self.scanner, self.version, self.on_scan, self.garbage, self.calls = scanner, version, on_scan, garbage, 0
        self.texts = {p.read_text(): p.name[:-len(".bundle.yaml")] for p in GOLDEN.glob("*.bundle.yaml")}

    def __call__(self, cmd, timeout, env):
        if "--version" in cmd or cmd[1:2] == ["version"]:
            return 0, (json.dumps({"Version": self.version}) if self.scanner == "trivy"
                       else f"Your current version is: {self.version}"), ""
        out = Path(cmd[cmd.index("--output") + 1])
        name = self.texts[(Path(cmd[-1]) / "bundle.yaml").read_text()]  # KeyError => not a captured variant
        out.write_text("{not json" if self.garbage else (GOLDEN / f"{self.scanner}__{name}.json").read_text())
        self.calls += 1
        if self.on_scan:
            self.on_scan(self.calls)
        return 0, "", ""


def make(tmp_path, catalog, mapping, scanner, version=None, **kw):
    cfg = {"trivy": {"binary": "trivy", "version": "0.75.0", "mode": "local-file", "timeout_s": 5,
                     "cache_dir": str(tmp_path / "tcache"), "flags": ["config", "--format", "json"]},
           "kubescape": {"binary": "kubescape", "version": "v4.0.15", "mode": "local-file", "timeout_s": 5,
                         "artifacts_dir": str(tmp_path / "ks"), "framework": "allcontrols"}}
    (tmp_path / "tcache/policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tcache/policy/metadata.json").write_text(json.dumps({"Digest": "sha256:aaa"}))
    (tmp_path / "ks").mkdir(exist_ok=True)
    for name in ("allcontrols.json", "controls-inputs.json", "exceptions.json"):    # all three are part of the policy digest
        (tmp_path / "ks" / name).write_text("{}")
    rp = Replay(scanner, version or cfg[scanner]["version"], **kw)
    sc = make_scanner(scanner, cfg, rp)
    return Runner(sc, mapping, catalog, tmp_path / "out"), rp, cfg


def case(runner, catalog, seed_name, mr_id, pick=lambda p: True):
    src = load_bundle(SEEDS / seed_name, seed_name)
    mr = catalog[mr_id]
    params = next(p for p in mr.generate_parameters(src, 9) if pick(p))
    return runner.run_pair(seed_name, src, mr, params)


def test_trivy_mr05_violation_with_full_artifacts(tmp_path, catalog, mapping):
    runner, _, _ = make(tmp_path, catalog, mapping, "trivy")
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "VIOLATION"
    bad = [k for k in r.assessment.key_results if k.outcome == "violation"]
    assert [(k.control, k.source, k.followup) for k in bad] == [("KSV-0113", "FAIL", "FAIL")]
    d = Path(r.case_dir)
    for f in ("source/bundle.yaml", "followup/bundle.yaml", "diff.patch", "scanner-source.json", "scanner-followup.json",
              "assessment.json", "provenance.json", "normalized-source.json", "normalized-followup.json"):
        assert (d / f).exists(), f
    prov = json.loads((d / "provenance.json").read_text())
    assert prov["scanner_version"] == "0.75.0" and prov["policy_digest"] == "sha256:aaa" and len(prov["source_text_sha256"]) == 64


def test_kubescape_k1_rediscovery_on_captured_report(tmp_path, catalog, mapping):
    runner, _, _ = make(tmp_path, catalog, mapping, "kubescape")
    r = case(runner, catalog, "rbac-workload", "MR-02", lambda p: p["profile"] == "secrets_read")
    assert r.result == "VIOLATION"
    assert [(k.control, k.source, k.followup) for k in r.assessment.key_results if k.outcome == "violation"] == [("C-0267", "PASS", "FAIL")]


def test_kubescape_mr05_is_satisfied_by_a_correct_scanner(tmp_path, catalog, mapping):
    runner, _, _ = make(tmp_path, catalog, mapping, "kubescape")
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "PASS"
    assert {(k.control, k.source, k.followup) for k in r.assessment.key_results} == {("C-0015", "FAIL", "PASS"), ("C-0267", "FAIL", "PASS")}


def test_source_scan_is_cached_but_followups_are_not(tmp_path, catalog, mapping):
    runner, rp, _ = make(tmp_path, catalog, mapping, "kubescape")
    src = load_bundle(SEEDS / "rbac-workload", "rbac-workload")
    mr = catalog["MR-02"]
    for p in mr.generate_parameters(src, 9):
        runner.run_pair("rbac-workload", src, mr, p)
    assert rp.calls == 3          # 1 shared source + 2 follow-ups (secrets_read, wildcard_admin)


def test_ut10_missing_binary_is_scan_error_with_clear_message(tmp_path, catalog, mapping):
    cfg = {"trivy": {"binary": "definitely-not-installed-xyz", "version": "0.75.0", "mode": "local-file", "timeout_s": 5,
                     "cache_dir": str(tmp_path), "flags": ["config"]}}
    runner = Runner(make_scanner("trivy", cfg), mapping, catalog, tmp_path / "out")
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "SCAN_ERROR" and "binary not found: definitely-not-installed-xyz" in r.reason


def test_invalid_json_report_is_scan_error(tmp_path, catalog, mapping):
    runner, _, _ = make(tmp_path, catalog, mapping, "trivy", garbage=True)
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "SCAN_ERROR" and "not valid JSON" in r.reason


def test_version_pin_violation_is_scan_error(tmp_path, catalog, mapping):
    runner, _, _ = make(tmp_path, catalog, mapping, "trivy", version="0.99.0")
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "SCAN_ERROR" and "version pin violated" in r.reason


def test_ut11_policy_change_between_scans_is_environment_mismatch_not_a_verdict(tmp_path, catalog, mapping):
    def bump(n):   # the checks bundle changes right after the first scan
        (tmp_path / "tcache/policy/metadata.json").write_text(json.dumps({"Digest": "sha256:bbb"}))
    runner, _, _ = make(tmp_path, catalog, mapping, "trivy", on_scan=bump)
    r = case(runner, catalog, "rbac-secrets-reader", "MR-05")
    assert r.result == "ENVIRONMENT_MISMATCH" and r.assessment is None


def test_invalid_source_is_reported_without_scanning(tmp_path, catalog, mapping):
    runner, rp, _ = make(tmp_path, catalog, mapping, "trivy")
    res = runner.run_seed(SEEDS / "invalid-missing-role")
    assert [(r.result, "missing dependency" in r.reason) for r in res] == [("INVALID_SOURCE", True)] and rp.calls == 0


def test_ut04_mr02_without_binding_is_skip_not_a_fake_pair(tmp_path, catalog, mapping):
    runner, rp, _ = make(tmp_path, catalog, mapping, "kubescape")
    res = runner.run_seed(SEEDS / "rbac-no-binding", ["MR-02"])
    assert [(r.result, r.reason) for r in res] == [("SKIP", "no_rolebinding")] and rp.calls == 0


def test_mr_without_scope_for_a_scanner_is_skipped_with_the_declared_reason_path(tmp_path, catalog, mapping):
    runner, rp, _ = make(tmp_path, catalog, mapping, "trivy")
    res = runner.run_seed(SEEDS / "rbac-workload", ["MR-02"])
    assert [(r.result, r.reason) for r in res] == [("SKIP", "mr_not_mapped_for_scanner")] and rp.calls == 0


def test_invalid_pair_is_never_scanned(tmp_path, catalog, mapping):
    class Bad(type(catalog["MR-04"])):
        def validate_pair(self, *a):
            return "INVALID_PAIR", "forced"
    bad = Bad()
    bad.spec = catalog["MR-04"].spec
    runner, rp, _ = make(tmp_path, {**catalog, "MR-04": bad}, mapping, "trivy")
    src = load_bundle(SEEDS / "pod-basic", "pod-basic")
    r = runner.run_pair("pod-basic", src, bad, bad.generate_parameters(src, 1)[0])
    assert (r.result, r.reason, rp.calls) == ("INVALID_PAIR", "forced", 0)


def test_no_reference_oracle_in_the_pipeline():
    """Design guard: the MR-first pipeline must not contain SAR / reference-oracle machinery."""
    forbidden = ("SubjectAccessReview", "ReferenceOracle", "DualOracle", "kubectl auth can-i")
    for f in (ROOT / "src").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        for w in forbidden:
            assert w not in text, f"{w} found in {f}"
