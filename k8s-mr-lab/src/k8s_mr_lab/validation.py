"""Structural diffing + source validation. This is NOT an oracle: it never predicts scanner verdicts,
it only proves that a follow-up differs from its source exactly the way the MR says it should."""
from __future__ import annotations

import difflib
from typing import Any

from .bundles import ConfigBundle, obj_key
from .model import ResKey, fmt_key


def _walk(a: Any, b: Any, path: str, out: list[dict]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in a.keys() | b.keys():
            p = f"{path}.{k}" if path else str(k)
            if k not in b:
                out.append({"op": "remove_field", "path": p, "old": a[k]})
            elif k not in a:
                out.append({"op": "add_field", "path": p, "new": b[k]})
            else:
                _walk(a[k], b[k], p, out)
    elif isinstance(a, list) and isinstance(b, list):
        for i in range(max(len(a), len(b))):
            p = f"{path}[{i}]"
            if i >= len(b):
                out.append({"op": "remove_item", "path": p, "old": a[i]})
            elif i >= len(a):
                out.append({"op": "add_item", "path": p, "new": b[i]})
            else:
                _walk(a[i], b[i], p, out)
    elif a != b or type(a) is not type(b):
        out.append({"op": "change", "path": path, "old": a, "new": b})


def diff_bundles(src: ConfigBundle, dst: ConfigBundle) -> list[dict]:
    """Deterministic, order-insensitive (for mapping keys) diff between two bundles."""
    si, di = src.index(), dst.index()
    out: list[dict] = []
    for k in sorted(si.keys() | di.keys()):
        if k not in di:
            out.append({"op": "remove_object", "object": fmt_key(k)})
        elif k not in si:
            out.append({"op": "add_object", "object": fmt_key(k), "new": di[k]})
        else:
            sub: list[dict] = []
            _walk(si[k], di[k], "", sub)
            for s in sub:
                s["object"] = fmt_key(k)
            out.extend(sorted(sub, key=lambda x: x["path"]))
    return out


def unified_text_diff(src: ConfigBundle, dst: ConfigBundle) -> str:
    return "".join(difflib.unified_diff(src.dump().splitlines(True), dst.dump().splitlines(True),
                                        "source/bundle.yaml", "followup/bundle.yaml"))


def validate_source(bundle: ConfigBundle) -> list[str]:
    return bundle.problems()


def only_object_changes(diff: list[dict], key_str: str) -> bool:
    return all(d.get("object") == key_str for d in diff)


def objects_with_namespace(bundle: ConfigBundle, ns: str) -> list[str]:
    return [fmt_key(obj_key(o)) for o in bundle.objects if obj_key(o)[2] == ns]


def expect_single_change(diff: list[dict], obj: ResKey, path: str, old, new) -> tuple[str, str]:
    """The diff must be exactly one in-place change `old -> new` at `path` of `obj` (shared by controlled-change MRs)."""
    if len(diff) != 1:
        return "INVALID_PAIR", f"expected_exactly_one_change_got_{len(diff)}"
    c = diff[0]
    if c["object"] != fmt_key(obj):
        return "INVALID_PAIR", "change_on_wrong_object"
    if c["op"] != "change" or c["path"] != path:
        return "INVALID_PAIR", f"change_on_{c['path']}_expected_{path}"
    if (type(c["old"]), c["old"], type(c["new"]), c["new"]) != (type(old), old, type(new), new):   # 1 != True here
        return "INVALID_PAIR", f"change_is_not_{old!r}_to_{new!r}"
    return "VALID_PAIR", ""
