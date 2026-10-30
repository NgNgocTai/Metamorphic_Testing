"""Trivy adapter: `trivy config` over a manifest directory, offline, with PASS results included."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .base import Scanner, expand


class TrivyScanner(Scanner):
    name = "trivy"

    def version_command(self) -> list[str]:
        return [self.binary, "--version", "--format", "json"]

    def parse_version(self, text: str) -> str:
        try:
            return json.loads(text[text.index("{"):text.rindex("}") + 1])["Version"]
        except (ValueError, KeyError):
            m = re.search(r"Version:\s*([0-9][^\s]*)", text)
            return m.group(1) if m else "unknown"

    def policy_digest(self) -> str:
        meta = expand(self.cfg.get("cache_dir", "~/.cache/trivy")) / "policy" / "metadata.json"
        try:
            return json.loads(meta.read_text())["Digest"]
        except (OSError, KeyError, ValueError):
            return "unknown"

    def build_command(self, target_dir: Path, out_json: Path) -> list[str]:
        flags = list(self.cfg.get("flags") or [])
        return [self.binary, *flags, "--cache-dir", str(expand(self.cfg.get("cache_dir", "~/.cache/trivy"))),
                "--output", str(out_json), str(target_dir)]
