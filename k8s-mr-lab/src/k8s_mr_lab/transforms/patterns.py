"""Reusable MR patterns. Only structure shared by at least two shipped MRs is abstracted here (see mrs/patterns.yaml).

PerCandidateMR   MR applies iff the source holds >= 1 candidate; one test case per candidate (MR-03, MR-04, MR-05).
ControlledChange KP3: set exactly one field to a new value; the pair is valid iff the diff is exactly that change
                 (MR-04, MR-05).
"""
from __future__ import annotations

from typing import Any, NamedTuple

from ..bundles import ConfigBundle
from ..model import ResKey
from ..validation import diff_bundles, expect_single_change
from .base import MetamorphicRelation


class PerCandidateMR(MetamorphicRelation):
    no_candidates_reason = "no_candidates"

    def candidates(self, source: ConfigBundle) -> list[Any]:
        raise NotImplementedError

    def candidate_params(self, candidate: Any) -> dict:
        raise NotImplementedError

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        return (True, "") if self.candidates(source) else (False, self.no_candidates_reason)

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        return [self.candidate_params(c) for c in self.candidates(source)][:max_cases]


class Change(NamedTuple):
    """The one edit a controlled-change MR performs: `obj`.`path` goes from `old` to `new`."""
    obj: ResKey
    path: str
    old: Any
    new: Any


class ControlledChange(PerCandidateMR):
    def expected_change(self, source: ConfigBundle, params: dict) -> Change | None:
        """The edit these params describe (None if they no longer fit the source). Drives validation."""
        raise NotImplementedError

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        ch = self.expected_change(source, params)
        if ch is None:
            return "INVALID_PAIR", "params_do_not_describe_a_change_on_source"
        return expect_single_change(diff_bundles(source, followup), *ch)
