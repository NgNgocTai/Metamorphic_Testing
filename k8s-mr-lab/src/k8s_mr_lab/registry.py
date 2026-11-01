"""MR registry. mrs/catalog.yaml is the single source of MR metadata; implementations bind to it with @implements."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import transforms  # noqa: F401  (imports every implementation module)
from .checker import RELATIONS
from .transforms.base import IMPLEMENTATIONS, MetamorphicRelation

REQUIRED_MR_FIELDS = ("id", "name", "category", "status", "pattern", "property_id", "property", "relation", "scope",
                      "preconditions", "transformation", "pair_checks", "counterexample", "limits")
STATUSES = ("mvp", "mvp_conditional", "candidate")
TEXT_FIELDS = ("name", "category", "pattern", "property_id", "property", "scope", "transformation", "counterexample")
LIST_FIELDS = ("preconditions", "pair_checks", "limits")
MR_ID = re.compile(r"MR-\d{2,}$")


class UnknownMRError(ValueError):
    """A requested MR id is not in the catalog (a run with 0 tests must never look like a valid result)."""


@dataclass(frozen=True)
class MappingEntry:
    control: str
    target: str


class PolicyMapping:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, path: str | Path) -> "PolicyMapping":
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def entries(self, mr_id: str, scanner: str) -> list[MappingEntry]:
        raw = ((self.data.get("mrs") or {}).get(mr_id) or {}).get(scanner) or []
        return [MappingEntry(e["control"], e["target"]) for e in raw]

    def control_kinds(self, scanner: str) -> dict[str, list[str]]:
        return {c: list(m.get("kinds") or []) for c, m in ((self.data.get("controls") or {}).get(scanner) or {}).items()}

    def control_meta(self, scanner: str, control: str) -> dict:
        return ((self.data.get("controls") or {}).get(scanner) or {}).get(control) or {}

    def supports(self, mr_id: str, scanner: str) -> bool:
        return bool(self.entries(mr_id, scanner))


def read_specs(path: str | Path) -> list[dict]:
    """Parse the catalog and check each entry's own schema (cross-file references: see mr_tools.check_traceability)."""
    specs = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["mrs"]
    seen: set[str] = set()
    for s in specs:
        mr_id = s.get("id", "<no id>")
        missing = [f for f in REQUIRED_MR_FIELDS if f not in s]
        if missing:
            raise ValueError(f"{mr_id}: missing required field(s) {missing}")
        if mr_id in seen:
            raise ValueError(f"duplicate MR id {mr_id}")
        seen.add(mr_id)
        if not isinstance(mr_id, str) or not MR_ID.match(mr_id):
            raise ValueError(f"{mr_id}: id must look like MR-01")
        for f in TEXT_FIELDS:
            if not isinstance(s[f], str) or not s[f].strip():
                raise ValueError(f"{mr_id}: field '{f}' must be a non-empty string")
        for f in LIST_FIELDS:
            if not isinstance(s[f], list) or not s[f] or not all(isinstance(x, str) and x.strip() for x in s[f]):
                raise ValueError(f"{mr_id}: field '{f}' must be a non-empty list of non-empty strings")
        if "all_failures" in s and not isinstance(s["all_failures"], bool):
            raise ValueError(f"{mr_id}: field 'all_failures' must be a boolean")
        if s["relation"] not in RELATIONS:
            raise ValueError(f"{mr_id}: unknown relation '{s['relation']}' (known: {sorted(RELATIONS)})")
        if s["status"] not in STATUSES:
            raise ValueError(f"{mr_id}: unknown status '{s['status']}' (known: {list(STATUSES)})")
    return specs


def load_catalog(path: str | Path) -> dict[str, MetamorphicRelation]:
    """Instantiate every catalog MR from its registered implementation. Fails loudly if the two disagree."""
    specs = {s["id"]: s for s in read_specs(path)}
    out: dict[str, MetamorphicRelation] = {}
    for mr_id, s in specs.items():
        cls = IMPLEMENTATIONS.get(mr_id)
        if cls is None:
            raise ValueError(f"catalog lists {mr_id} without an @implements('{mr_id}') class")
        mr = cls()
        mr.bind(s)
        out[mr_id] = mr
    extra = set(IMPLEMENTATIONS) - set(specs)
    if extra:
        raise ValueError(f"implemented but missing from catalog: {sorted(extra)}")
    return out


def active_mrs(catalog: dict[str, MetamorphicRelation], mr_ids: list[str] | None = None) -> list[MetamorphicRelation]:
    """MRs a run executes: those named explicitly, else every non-candidate (candidates need an explicit --mr)."""
    if mr_ids:
        unknown = sorted(set(mr_ids) - set(catalog))
        if unknown:
            raise UnknownMRError(f"unknown MR id(s) {unknown}; catalog has {sorted(catalog)}")
        return [m for m in catalog.values() if m.id in mr_ids]
    return [m for m in catalog.values() if m.spec.get("status") != "candidate"]
