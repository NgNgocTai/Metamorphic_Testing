"""ConfigBundle: a set of related Kubernetes objects, with strict YAML I/O, stable hashing and spans."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from .model import ResKey


class BundleError(ValueError):
    pass


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys instead of silently overwriting."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False):
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise BundleError(f"duplicate mapping key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def api_group(obj: dict) -> str:
    av = str(obj.get("apiVersion", ""))
    return av.split("/")[0] if "/" in av else ""


def obj_key(obj: dict) -> ResKey:
    meta = obj.get("metadata") or {}
    return (api_group(obj), str(obj.get("kind", "")), str(meta.get("namespace", "") or ""), str(meta.get("name", "")))


def canonical_json(objs: Iterable[dict]) -> str:
    return json.dumps(list(objs), sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class Span:
    start: int  # 1-based inclusive line range of the object inside the dumped file
    end: int
    key: ResKey


@dataclass
class ConfigBundle:
    objects: list[dict]
    source_path: str = ""
    id: str = ""

    # ------------------------------------------------------------------ identity
    def keys(self) -> list[ResKey]:
        return [obj_key(o) for o in self.objects]

    def index(self) -> dict[ResKey, dict]:
        return {obj_key(o): o for o in self.objects}

    def find(self, kind: str, namespace: str, name: str) -> dict | None:
        for o in self.objects:
            _, k, ns, n = obj_key(o)
            if k == kind and ns == namespace and n == name:
                return o
        return None

    def of_kind(self, *kinds: str) -> list[dict]:
        return [o for o in self.objects if o.get("kind") in kinds]

    def clone(self) -> "ConfigBundle":
        return ConfigBundle(copy.deepcopy(self.objects), self.source_path, self.id)

    # ------------------------------------------------------------------ hashing
    def semantic_digest(self) -> str:
        """Digest of the parsed content; invariant to mapping-key order and formatting."""
        return hashlib.sha256(canonical_json(self.objects).encode()).hexdigest()

    def text_digest(self) -> str:
        return hashlib.sha256(self.dump().encode()).hexdigest()

    # ------------------------------------------------------------------ I/O
    def dump(self) -> str:
        return self.dump_with_spans()[0]

    def dump_with_spans(self) -> tuple[str, list[Span]]:
        parts: list[str] = []
        spans: list[Span] = []
        line = 1
        for i, o in enumerate(self.objects):
            text = yaml.safe_dump(o, sort_keys=False, default_flow_style=False, allow_unicode=True)
            if i > 0:
                parts.append("---\n")
                line += 1
            n = text.count("\n")
            spans.append(Span(line, line + n - 1, obj_key(o)))
            parts.append(text)
            line += n
        return "".join(parts), spans

    def write(self, directory: Path) -> tuple[Path, list[Span]]:
        directory.mkdir(parents=True, exist_ok=True)
        text, spans = self.dump_with_spans()
        path = directory / "bundle.yaml"
        path.write_text(text, encoding="utf-8")
        return path, spans

    # ------------------------------------------------------------------ validation
    def problems(self) -> list[str]:
        """Structural problems that make the bundle unusable as a source input."""
        out: list[str] = []
        seen: set[ResKey] = set()
        for o in self.objects:
            if not isinstance(o, dict) or not o.get("kind") or not o.get("apiVersion"):
                out.append("object without kind/apiVersion")
                continue
            k = obj_key(o)
            if not k[3]:
                out.append(f"{k[1]} without metadata.name")
            if k in seen:
                out.append(f"duplicate object {k}")
            seen.add(k)
        idx = self.index()
        for o in self.of_kind("RoleBinding"):
            ref = o.get("roleRef") or {}
            ns = obj_key(o)[2]
            if ref.get("kind") == "Role" and ("rbac.authorization.k8s.io", "Role", ns, ref.get("name", "")) not in idx:
                out.append(f"missing dependency: RoleBinding {ns}/{obj_key(o)[3]} -> Role {ns}/{ref.get('name')}")
        return out


def parse_documents(text: str) -> list[dict]:
    docs = []
    for d in yaml.load_all(text, Loader=_StrictLoader):
        if d is None:
            continue
        if not isinstance(d, dict):
            raise BundleError("YAML document is not a mapping")
        docs.append(d)
    return docs


def load_bundle(path: str | Path, bundle_id: str = "") -> ConfigBundle:
    """Load every *.yaml/*.yml under `path` (file or directory) into one bundle."""
    p = Path(path)
    files = [p] if p.is_file() else sorted([*p.glob("*.yaml"), *p.glob("*.yml")])
    if not files:
        raise BundleError(f"no YAML files under {p}")
    objs: list[dict] = []
    for f in files:
        try:
            objs.extend(parse_documents(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as e:
            raise BundleError(f"{f}: {e}") from e
        except BundleError as e:
            raise BundleError(f"{f}: {e}") from e
    return ConfigBundle(objs, str(p), bundle_id or (p.stem if p.is_file() else p.name))
