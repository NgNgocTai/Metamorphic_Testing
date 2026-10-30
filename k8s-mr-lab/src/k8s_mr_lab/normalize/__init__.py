from __future__ import annotations

from ..bundles import ConfigBundle, Span
from ..model import NormalizedReport
from . import kubescape as _ks
from . import trivy as _tv


def normalize(scanner: str, raw: dict, bundle: ConfigBundle, spans: list[Span], control_kinds: dict[str, list[str]]) -> NormalizedReport:
    if scanner == "trivy":
        return _tv.normalize(raw, bundle, spans, control_kinds)
    if scanner == "kubescape":
        return _ks.normalize(raw, bundle)
    raise KeyError(scanner)
