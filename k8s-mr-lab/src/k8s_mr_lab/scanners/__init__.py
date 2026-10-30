from __future__ import annotations

from pathlib import Path

import yaml

from .base import Runner, Scanner, subprocess_runner
from .kubescape import KubescapeScanner
from .trivy import TrivyScanner

SCANNERS = {"trivy": TrivyScanner, "kubescape": KubescapeScanner}


def load_scanner_config(path: str | Path = "config/scanners.yaml") -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def make_scanner(name: str, config: dict, runner: Runner = subprocess_runner) -> Scanner:
    return SCANNERS[name](config[name], runner)
