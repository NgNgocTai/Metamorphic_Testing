"""Base class of an executable Metamorphic Relation: (Precondition, Transformation, ExpectedRelation, Scope).

Metadata (name, category, relation, pattern, ...) lives only in mrs/catalog.yaml; `load_catalog` copies it onto the
instance. A class binds itself to its catalog entry with `@implements("MR-xx")` and is discovered automatically.
"""
from __future__ import annotations

from typing import Any, Callable

from ..bundles import ConfigBundle
from ..model import ResKey

IMPLEMENTATIONS: dict[str, type["MetamorphicRelation"]] = {}


def implements(mr_id: str) -> Callable[[type], type]:
    """Class decorator: bind an implementation to the catalog entry `mr_id`."""
    def deco(cls: type) -> type:
        if mr_id in IMPLEMENTATIONS:
            raise ValueError(f"{mr_id} is implemented twice ({IMPLEMENTATIONS[mr_id].__name__}, {cls.__name__})")
        cls.id = mr_id
        IMPLEMENTATIONS[mr_id] = cls
        return cls
    return deco


def key_to_list(k: ResKey) -> list[str]:
    return list(k)


def list_to_key(v: Any) -> ResKey:
    return (v[0], v[1], v[2], v[3])


class MetamorphicRelation:
    id = ""                       # set by @implements
    name = ""                     # everything below is filled from the catalog entry by load_catalog()
    category = ""
    pattern = ""
    property_id = ""
    relation = "equal"            # a key of checker.RELATIONS (equal | pass_to_fail | fail_to_pass | custom)
    all_failures = False          # also compare every FAIL (control, resource) seen in either report
    spec: dict = {}
    # (evidence key, regex): what a static look at a violating rule's source should contain for this MR's property to be considered
    # by the check at all. Triage aid for the human adjudicator, never an oracle. None = no such probe.
    rule_probe: tuple[str, str] | None = None

    def bind(self, spec: dict) -> None:
        self.spec = spec
        self.name = spec["name"]
        self.category = spec["category"]
        self.pattern = spec["pattern"]
        self.property_id = spec["property_id"]
        self.relation = spec["relation"]
        self.all_failures = bool(spec.get("all_failures", False))

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
