"""Kubescape adapter: `kubescape scan framework allcontrols <dir>` over manifests, offline artifacts."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Scanner, expand, sha256_files


class KubescapeScanner(Scanner):
    name = "kubescape"

    def version_command(self) -> list[str]:
        return [self.binary, "version"]

    def parse_version(self, text: str) -> str:
        m = re.search(r"current version is:\s*(v[0-9][^\s]*)", text) or re.search(r"\b(v[0-9]+\.[0-9]+\.[0-9]+)\b", text)
        return m.group(1) if m else "unknown"

    def policy_digest(self) -> str:
        art = expand(self.cfg.get("artifacts_dir", "~/.kubescape"))
        fw = self.cfg.get("framework", "allcontrols")
        return sha256_files([art / f"{fw}.json", art / "controls-inputs.json", art / "exceptions.json"])

    def build_command(self, target_dir: Path, out_json: Path) -> list[str]:
        return [self.binary, "scan", "framework", self.cfg.get("framework", "allcontrols"),
                "--keep-local", "--verbose", "--format", "json", "--output", str(out_json),
                "--use-artifacts-from", str(expand(self.cfg.get("artifacts_dir", "~/.kubescape"))), str(target_dir)]
