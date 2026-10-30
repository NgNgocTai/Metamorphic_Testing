"""Base class of an executable Metamorphic Relation: (Precondition, Transformation, ExpectedRelation, Scope)."""
from __future__ import annotations

from typing import Any

from ..bundles import ConfigBundle
from ..model import ResKey


def key_to_list(k: ResKey) -> list[str]:
    return list(k)


def list_to_key(v: Any) -> ResKey:
    return (v[0], v[1], v[2], v[3])


class MetamorphicRelation:
    id = ""
    name = ""
    category = ""
    property = ""
    relation = "equal"            # equal | pass_to_fail | fail_to_pass
    all_failures = False          # also compare every FAIL (control, resource) seen in either report
    spec: dict = {}               # filled from mrs/catalog.yaml by the registry

    # --- precondition ------------------------------------------------------------------
    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        """Return (True, '') or (False, reason). Must inspect structure, not just field presence."""
        raise NotImplementedError

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        raise NotImplementedError

    # --- transformation ------------------------------------------------------------------
    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        """Clone `source`, apply the change, return (follow-up, trace). Must never mutate `source`."""
        raise NotImplementedError

    # --- structural pair validation (not an oracle) ----------------------------------------
    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        """Return ('VALID_PAIR'|'INVALID_PAIR'|'INCONCLUSIVE', reason)."""
        raise NotImplementedError

    # --- scope: which resources the mapped controls are compared on ---------------------------
    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {}
