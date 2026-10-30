from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import ConfigBundle, Span, load_bundle  # noqa: E402
from k8s_mr_lab.registry import PolicyMapping, load_catalog  # noqa: E402

GOLDEN = ROOT / "tests" / "golden"
SEEDS = ROOT / "seeds" / "synthetic"


@pytest.fixture(scope="session")
def catalog():
    return load_catalog(ROOT / "mrs" / "catalog.yaml")


@pytest.fixture(scope="session")
def mapping():
    return PolicyMapping.load(ROOT / "config" / "policy-mapping.yaml")


@pytest.fixture()
def seed():
    def _load(name: str) -> ConfigBundle:
        return load_bundle(SEEDS / name, name)
    return _load


def load_golden(scanner: str, name: str) -> tuple[dict, ConfigBundle, list[Span]]:
    """Raw report captured from the REAL scanner + the exact bundle text/spans that were scanned."""
    raw = json.loads((GOLDEN / f"{scanner}__{name}.json").read_text(encoding="utf-8"))
    bundle = load_bundle(GOLDEN / f"{name}.bundle.yaml", name)
    spans = [Span(a, b, tuple(k)) for a, b, k in json.loads((GOLDEN / f"{name}.spans.json").read_text())]
    return raw, bundle, spans


@pytest.fixture()
def golden():
    return load_golden


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None
