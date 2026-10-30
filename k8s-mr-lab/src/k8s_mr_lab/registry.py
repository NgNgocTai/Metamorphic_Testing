"""MR registry: binds catalog metadata (mrs/catalog.yaml) to executable MR classes and the control scope mapping."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .transforms.base import MetamorphicRelation
from .transforms.pod_privileged import PrivilegedFlip
from .transforms.rbac_api_group import ApiGroupSwitch
from .transforms.rbac_decoy_role import DecoySameNameRole
from .transforms.rbac_split_verbs import SplitRuleVerbs
from .transforms.yaml_reorder import YamlKeyOrder

MR_CLASSES = [YamlKeyOrder, DecoySameNameRole, SplitRuleVerbs, PrivilegedFlip, ApiGroupSwitch]


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


def load_catalog(path: str | Path) -> dict[str, MetamorphicRelation]:
    """Instantiate every MR and attach its catalog spec. Fails loudly if catalog and code disagree."""
    spec = {m["id"]: m for m in yaml.safe_load(Path(path).read_text(encoding="utf-8"))["mrs"]}
    out: dict[str, MetamorphicRelation] = {}
    for cls in MR_CLASSES:
        mr = cls()
        if mr.id not in spec:
            raise ValueError(f"{mr.id} implemented but missing from catalog")
        s = spec[mr.id]
        if s["relation"] != mr.relation:
            raise ValueError(f"{mr.id}: catalog relation {s['relation']} != code relation {mr.relation}")
        mr.spec = s
        out[mr.id] = mr
    extra = set(spec) - set(out)
    if extra:
        raise ValueError(f"catalog lists MRs without implementation: {sorted(extra)}")
    return out
