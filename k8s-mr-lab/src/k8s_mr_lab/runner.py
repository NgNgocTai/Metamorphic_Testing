"""Experiment runner: seed -> applicable MR -> (source, follow-up) -> same scanner twice -> normalize -> MR check."""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .bundles import BundleError, ConfigBundle, Span, load_bundle
from .checker import check, full_keys, static_keys
from .informative import annotate, changed_objects
from .model import (R_ENV_MISMATCH, R_INCONCLUSIVE, R_INVALID_PAIR, R_INVALID_SOURCE, R_SCAN_ERROR, R_SKIP, VALID_PAIR,
                    Assessment, NormalizedReport, ScannerInvocation, fmt_key)
from .normalize import normalize
from .registry import PolicyMapping, active_mrs
from .scanners.base import Scanner
from .transforms.base import MetamorphicRelation
from .validation import diff_bundles, unified_text_diff, validate_source


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:10]


@dataclass
class Scan:
    inv: ScannerInvocation
    spans: list[Span]
    raw: dict | None = None
    report: NormalizedReport | None = None


@dataclass
class CaseResult:
    case_id: str
    seed_id: str
    mr_id: str
    scanner: str
    result: str
    reason: str = ""
    params: dict = field(default_factory=dict)
    pair_status: str = ""
    assessment: Assessment | None = None
    source_inv: ScannerInvocation | None = None
    followup_inv: ScannerInvocation | None = None
    invocations: int = 0
    elapsed_ms: int = 0
    case_dir: str = ""
    gen_ms: int = 0              # transform + structural validation + writing artifacts
    scan_ms: int = 0             # scanner time actually spent in THIS case (cache hits cost 0)
    cache_hits: int = 0
    source_sha: str = ""         # sha256 of the exact scanned text (dedup key)
    followup_sha: str = ""


class Runner:
    def __init__(self, scanner: Scanner, mapping: PolicyMapping, catalog: dict[str, MetamorphicRelation],
                 out_dir: Path, use_cache: bool = True):
        self.scanner, self.mapping, self.catalog = scanner, mapping, catalog
        self.out = Path(out_dir)
        self.run_id = f"{scanner.name}-{time.strftime('%Y%m%dT%H%M%S')}"
        self.use_cache = use_cache
        self._cache: dict[str, Scan] = {}
        self.total_invocations = 0
        self.kinds = mapping.control_kinds(scanner.name)

    # ------------------------------------------------------------------ scanning
    def _scan(self, bundle: ConfigBundle, workdir: Path, name: str) -> tuple[Scan, bool]:
        """Scan `bundle` in workdir/<name>/; returns (scan, executed_now)."""
        text_digest = bundle.text_digest()
        if self.use_cache and text_digest in self._cache:
            return self._cache[text_digest], False
        d = workdir / name
        path, spans = bundle.write(d)
        out_json = workdir / f"scanner-{name}.json"
        inv = self.scanner.execute(path.parent, out_json)
        self.total_invocations += 1
        scan = Scan(inv, spans)
        if inv.ok:
            scan.raw = json.loads(out_json.read_text(encoding="utf-8"))
            scan.report = normalize(self.scanner.name, scan.raw, bundle, spans, self.kinds)
        if self.use_cache and inv.ok:
            self._cache[text_digest] = scan
        return scan, True

    # ------------------------------------------------------------------ one pair
    def run_pair(self, seed_id: str, source: ConfigBundle, mr: MetamorphicRelation, params: dict,
                 case_id: str | None = None) -> CaseResult:
        t0 = time.monotonic()
        case_id = case_id or f"{mr.id}__{seed_id}__{digest(params)}"
        cdir = self.out / "cases" / case_id
        cdir.mkdir(parents=True, exist_ok=True)
        cr = CaseResult(case_id, seed_id, mr.id, self.scanner.name, R_SKIP, params=params, case_dir=str(cdir))

        followup, trace = mr.transform(source, params)
        pair_status, why = mr.validate_pair(source, followup, params)
        cr.pair_status = pair_status
        cr.source_sha, cr.followup_sha = source.text_digest(), followup.text_digest()
        (cdir / "source").mkdir(exist_ok=True)
        (cdir / "followup").mkdir(exist_ok=True)
        source.write(cdir / "source")
        followup.write(cdir / "followup")
        diff = diff_bundles(source, followup)
        (cdir / "diff.patch").write_text(unified_text_diff(source, followup), encoding="utf-8")
        (cdir / "diff.json").write_text(json.dumps(diff, indent=2, default=str), encoding="utf-8")
        (cdir / "trace.json").write_text(json.dumps({"mr": mr.id, "params": params, **trace}, indent=2), encoding="utf-8")

        if pair_status != VALID_PAIR:
            cr.result = R_INVALID_PAIR if pair_status == R_INVALID_PAIR else R_INCONCLUSIVE
            cr.reason = why
            return self._finish(cr, cdir, t0)

        entries = self.mapping.entries(mr.id, self.scanner.name)
        static = static_keys(mr, entries, self.kinds, source, params)
        if not static and not mr.all_failures:
            cr.result, cr.reason = R_SKIP, "no_mapped_control_applies_to_this_seed"
            return self._finish(cr, cdir, t0)

        cr.gen_ms = int((time.monotonic() - t0) * 1000)
        s1, ran1 = self._scan(source, cdir, "source")
        s2, ran2 = self._scan(followup, cdir, "followup")
        cr.source_inv, cr.followup_inv = s1.inv, s2.inv
        cr.invocations = int(ran1) + int(ran2)
        cr.cache_hits = 2 - cr.invocations
        cr.scan_ms = (s1.inv.elapsed_ms if ran1 else 0) + (s2.inv.elapsed_ms if ran2 else 0)
        for tag, sc in (("source", s1), ("followup", s2)):
            (cdir / f"invocation-{tag}.json").write_text(json.dumps(sc.inv.meta(), indent=2), encoding="utf-8")
            (cdir / f"spans-{tag}.json").write_text(json.dumps([[s.start, s.end, list(s.key)] for s in sc.spans]), encoding="utf-8")
        for tag, sc in (("source", s1), ("followup", s2)):
            raw = Path(sc.inv.raw_path) if sc.inv.raw_path else None
            if raw and raw.exists() and raw.parent != cdir:
                (cdir / f"scanner-{tag}.json").write_text(raw.read_text(encoding="utf-8"), encoding="utf-8")

        if not (s1.inv.ok and s2.inv.ok):
            cr.result = R_SCAN_ERROR
            cr.reason = "; ".join(f"{t}: {s.inv.error}" for t, s in (("source", s1), ("followup", s2)) if not s.inv.ok)
            return self._finish(cr, cdir, t0)
        env1 = (s1.inv.version, s1.inv.mode, s1.inv.policy_digest)
        env2 = (s2.inv.version, s2.inv.mode, s2.inv.policy_digest)
        if env1 != env2:
            cr.result, cr.reason = R_ENV_MISMATCH, f"source {env1} != followup {env2}"
            return self._finish(cr, cdir, t0)

        (cdir / "normalized-source.json").write_text(json.dumps(s1.report.to_json(), indent=2), encoding="utf-8")
        (cdir / "normalized-followup.json").write_text(json.dumps(s2.report.to_json(), indent=2), encoding="utf-8")
        a = check(mr, full_keys(mr, static, s1.report, s2.report), s1.report, s2.report)
        annotate(a, self.mapping, self.scanner.name, mr.id, changed_objects(diff))
        cr.assessment, cr.result, cr.reason = a, a.result, a.reason
        return self._finish(cr, cdir, t0)

    def _finish(self, cr: CaseResult, cdir: Path, t0: float) -> CaseResult:
        cr.elapsed_ms = int((time.monotonic() - t0) * 1000)
        if not cr.gen_ms:
            cr.gen_ms = cr.elapsed_ms
        (cdir / "assessment.json").write_text(json.dumps({
            "case_id": cr.case_id, "result": cr.result, "reason": cr.reason, "pair_status": cr.pair_status,
            "assessment": cr.assessment.to_json() if cr.assessment else None}, indent=2), encoding="utf-8")
        inv = cr.source_inv
        (cdir / "provenance.json").write_text(json.dumps({
            "framework": f"k8s-mr-lab {__version__}", "run_id": self.run_id, "seed_id": cr.seed_id, "mr_id": cr.mr_id,
            "mr_spec_digest": digest(self.catalog[cr.mr_id].spec), "params": cr.params,
            "random_seed": None, "scanner": cr.scanner,
            "scanner_version": inv.version if inv else None, "scan_mode": inv.mode if inv else None,
            "policy_digest": inv.policy_digest if inv else None,
            "mapping_digest": self.mapping.digest(), "source_text_sha256": _file_sha(cdir / "source" / "bundle.yaml"),
            "followup_text_sha256": _file_sha(cdir / "followup" / "bundle.yaml"),
            "python": sys.version.split()[0], "platform": platform.platform()}, indent=2), encoding="utf-8")
        return cr

    # ------------------------------------------------------------------ one seed
    def run_seed(self, seed_dir: Path, mr_ids: list[str] | None = None, max_cases: int = 4) -> list[CaseResult]:
        seed_id = seed_dir.name
        base = dict(seed_id=seed_id, scanner=self.scanner.name)
        try:
            source = load_bundle(seed_dir, seed_id)
        except BundleError as e:
            return [CaseResult(f"INVALID_SOURCE__{seed_id}", mr_id="*", result=R_INVALID_SOURCE, reason=str(e), **base)]
        problems = validate_source(source)
        if problems:
            return [CaseResult(f"INVALID_SOURCE__{seed_id}", mr_id="*", result=R_INVALID_SOURCE, reason="; ".join(problems), **base)]
        out: list[CaseResult] = []
        for mr in active_mrs(self.catalog, mr_ids):
            skip = lambda why: out.append(CaseResult(f"{mr.id}__{seed_id}__skip", mr_id=mr.id, result=R_SKIP, reason=why, **base))
            if not self.mapping.supports(mr.id, self.scanner.name):
                skip("mr_not_mapped_for_scanner")
                continue
            ok, why = mr.applicable(source)
            if not ok:
                skip(why)
                continue
            plist = mr.generate_parameters(source, max_cases)
            if not plist:
                skip("no_parameters_generated")
                continue
            for params in plist:
                out.append(self.run_pair(seed_id, source, mr, params))
        return out

    def environment_lock(self) -> dict:
        return {"framework": f"k8s-mr-lab {__version__}", "scanner": self.scanner.name,
                "scanner_version": self.scanner.version(), "scan_mode": self.scanner.mode,
                "policy_digest": self.scanner.policy_digest(), "pinned_version": self.scanner.cfg.get("version"),
                "mapping_digest": self.mapping.digest(), "python": sys.version.split()[0],
                "platform": platform.platform(), "run_id": self.run_id}


def _file_sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else ""
