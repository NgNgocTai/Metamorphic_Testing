"""MR-01 — YAML key order. Reordering mapping keys never changes the parsed object."""
from __future__ import annotations

from typing import Any

from ..bundles import ConfigBundle
from ..model import VALID_PAIR
from .base import MetamorphicRelation, implements

R_INVALID_PAIR = "INVALID_PAIR"


def reorder(value: Any, mode: str) -> Any:
    if isinstance(value, dict):
        items = [(k, reorder(v, mode)) for k, v in value.items()]
        if mode == "reverse":
            items.reverse()
        elif mode == "sorted":
            items.sort(key=lambda kv: str(kv[0]))
        else:
            raise ValueError(f"unknown reorder mode {mode}")
        return dict(items)
    if isinstance(value, list):  # sequence order is semantic: keep it, only reorder nested mappings
        return [reorder(v, mode) for v in value]
    return value


@implements("MR-01")
class YamlKeyOrder(MetamorphicRelation):

    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        if not source.objects:
            return False, "empty_bundle"
        return True, ""

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        out = []
        for mode in ("reverse", "sorted"):
            if self.transform(source, {"mode": mode})[0].dump() != source.dump():  # skip no-op reorders
                out.append({"mode": mode})
        return out[:max_cases]

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()
        fu.objects = [reorder(o, params["mode"]) for o in fu.objects]
        return fu, {"operation": "yaml.reorder_mapping_keys", "mode": params["mode"], "object_mapping": "identity"}

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        if source.semantic_digest() != followup.semantic_digest():
            return R_INVALID_PAIR, "parsed_content_changed"
        if [o.get("kind") for o in source.objects] != [o.get("kind") for o in followup.objects]:
            return R_INVALID_PAIR, "document_order_changed"
        if source.dump() == followup.dump():
            return R_INVALID_PAIR, "followup_text_identical_to_source"
        return VALID_PAIR, ""
