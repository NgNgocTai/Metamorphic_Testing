"""Core data model. Statuses are deliberately distinct: absence of a finding is never PASS."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# (apiGroup, kind, namespace, name); cluster-scoped objects use namespace "".
ResKey = tuple[str, str, str, str]

# Verdict of one scanner control on one resource.
PASS, FAIL, NOT_EVALUATED, UNKNOWN, EXCLUDED = "PASS", "FAIL", "NOT_EVALUATED", "UNKNOWN", "EXCLUDED"
CONCLUSIVE = (PASS, FAIL)

# Outcome of one MR comparison / case.
R_PASS, R_VIOLATION, R_SKIP = "PASS", "VIOLATION", "SKIP"
R_INVALID_SOURCE, R_INVALID_PAIR = "INVALID_SOURCE", "INVALID_PAIR"
R_INCONCLUSIVE, R_SCAN_ERROR, R_ENV_MISMATCH = "INCONCLUSIVE", "SCAN_ERROR", "ENVIRONMENT_MISMATCH"
RESULT_STATUSES = (R_PASS, R_VIOLATION, R_SKIP, R_INVALID_SOURCE, R_INVALID_PAIR,
                   R_INCONCLUSIVE, R_SCAN_ERROR, R_ENV_MISMATCH)

VALID_PAIR = "VALID_PAIR"

EQUAL, PASS_TO_FAIL, FAIL_TO_PASS = "equal", "pass_to_fail", "fail_to_pass"


def fmt_key(key: ResKey) -> str:
    group, kind, ns, name = key
    return f"{kind}/{ns + '/' if ns else ''}{name}" + (f"@{group}" if group else "")


@dataclass(frozen=True)
class CanonicalVerdict:
    scanner: str
    control_id: str
    resource_key: ResKey
    status: str
    evidence: tuple = ()


@dataclass
class NormalizedReport:
    """Per-(control, resource) verdicts distilled from one raw scanner report."""
    scanner: str
    verdicts: dict[tuple[str, ResKey], CanonicalVerdict] = field(default_factory=dict)
    unattributed_failures: list[tuple[str, str]] = field(default_factory=list)  # (control, why)
    notes: list[str] = field(default_factory=list)

    def add(self, control: str, key: ResKey, status: str, *evidence: str) -> None:
        self.verdicts[(control, key)] = CanonicalVerdict(self.scanner, control, key, status, tuple(evidence))

    def get(self, control: str, key: ResKey) -> CanonicalVerdict:
        v = self.verdicts.get((control, key))
        return v if v else CanonicalVerdict(self.scanner, control, key, NOT_EVALUATED, ("no_verdict_in_report",))

    def failed_keys(self) -> set[tuple[str, ResKey]]:
        return {k for k, v in self.verdicts.items() if v.status == FAIL}

    def to_json(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "verdicts": [
                {"control": v.control_id, "resource": fmt_key(v.resource_key), "status": v.status,
                 "evidence": list(v.evidence)}
                for _, v in sorted(self.verdicts.items(), key=lambda kv: (kv[0][0], fmt_key(kv[0][1])))
            ],
            "unattributed_failures": self.unattributed_failures,
            "notes": self.notes,
        }


@dataclass
class ScannerInvocation:
    tool: str
    version: str
    mode: str
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int
    policy_digest: str
    raw_path: str | None = None
    error: str | None = None  # set => SCAN_ERROR (binary missing, timeout, bad JSON, ...)

    @property
    def ok(self) -> bool:
        return self.error is None

    def meta(self) -> dict[str, Any]:
        return {"tool": self.tool, "version": self.version, "mode": self.mode, "command": self.command,
                "exit_code": self.exit_code, "elapsed_ms": self.elapsed_ms, "policy_digest": self.policy_digest,
                "raw_path": self.raw_path, "error": self.error,
                "stderr_tail": self.stderr[-600:]}


@dataclass
class KeyResult:
    control: str
    resource: ResKey
    source: str
    followup: str
    outcome: str  # ok | violation | inconclusive
    reason: str = ""


@dataclass
class Assessment:
    result: str
    relation: str
    reason: str = ""
    key_results: list[KeyResult] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {"ok": 0, "violation": 0, "inconclusive": 0}
        for k in self.key_results:
            c[k.outcome] += 1
        return c

    def to_json(self) -> dict[str, Any]:
        return {"result": self.result, "relation": self.relation, "reason": self.reason, "counts": self.counts(),
                "comparisons": [{"control": k.control, "resource": fmt_key(k.resource), "source": k.source,
                                 "followup": k.followup, "outcome": k.outcome, "reason": k.reason}
                                for k in self.key_results]}
