"""Scanner adapter base: runs the REAL CLI via subprocess and captures everything needed to replay it."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable

from ..model import ScannerInvocation

# (command, timeout_s, env_overrides) -> (exit_code, stdout, stderr). Injected in unit tests; never a fake scanner.
Runner = Callable[[list[str], int, dict[str, str]], tuple[int, str, str]]


def subprocess_runner(cmd: list[str], timeout: int, env: dict[str, str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **env})
    return p.returncode, p.stdout, p.stderr


def expand(path: str) -> Path:
    return Path(os.path.expanduser(path))


def sha256_files(paths: list[Path]) -> str:
    """Digest of the policy files; 'unknown' if any is missing (never hash a placeholder as if it were data)."""
    if not all(p.exists() for p in paths):
        return "unknown"
    h = hashlib.sha256()
    for p in paths:
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


class Scanner:
    name = ""

    def __init__(self, cfg: dict, runner: Runner = subprocess_runner):
        self.cfg = cfg
        self.runner = runner
        self.binary = cfg["binary"]
        self.mode = cfg["mode"]
        self.timeout = int(cfg.get("timeout_s", 120))
        self.env = dict(cfg.get("env") or {})

    # --- to be provided by subclasses -------------------------------------------------------
    def build_command(self, target_dir: Path, out_json: Path) -> list[str]:
        raise NotImplementedError

    def parse_version(self, text: str) -> str:
        raise NotImplementedError

    def version_command(self) -> list[str]:
        raise NotImplementedError

    def policy_digest(self) -> str:
        raise NotImplementedError

    # --- shared -----------------------------------------------------------------------------
    def version(self) -> str:
        try:
            code, out, err = self.runner(self.version_command(), 30, self.env)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return f"unavailable: {type(e).__name__}"
        return self.parse_version(out + "\n" + err)

    def execute(self, target_dir: Path, out_json: Path) -> ScannerInvocation:
        """Scan `target_dir` (a directory holding bundle.yaml) and write the raw JSON report to `out_json`."""
        cmd = self.build_command(target_dir, out_json)
        inv = ScannerInvocation(self.name, "", self.mode, cmd, None, "", "", 0, "")
        t0 = time.monotonic()
        try:
            inv.version = self.version()
            inv.policy_digest = self.policy_digest()
            code, out, err = self.runner(cmd, self.timeout, self.env)
            inv.exit_code, inv.stdout, inv.stderr = code, out, err
        except FileNotFoundError:
            inv.error = f"binary not found: {self.binary} (install it or fix config/scanners.yaml)"
        except subprocess.TimeoutExpired:
            inv.error = f"timeout after {self.timeout}s"
        inv.elapsed_ms = int((time.monotonic() - t0) * 1000)
        if inv.error:
            return inv
        # Verified on the pinned versions: both scanners exit 0 even when they report failures, so any other code is an
        # error of the run itself, whatever the JSON on disk looks like.
        accepted = [int(c) for c in self.cfg.get("accepted_exit_codes", [0])]
        if inv.exit_code not in accepted:
            inv.error = f"exit code {inv.exit_code} not in accepted {accepted}: {inv.stderr[-300:]}"
            return inv
        if inv.policy_digest in ("", "unknown"):
            inv.error = "policy digest unavailable: refusing to score against an unidentified policy set"
            return inv
        if not out_json.exists() or out_json.stat().st_size == 0:
            inv.error = f"no JSON report produced (exit {inv.exit_code}): {inv.stderr[-300:]}"
            return inv
        try:
            json.loads(out_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            inv.error = f"report is not valid JSON: {e}"
            return inv
        inv.raw_path = str(out_json)
        pinned = str(self.cfg.get("version", ""))
        if pinned and inv.version != pinned:
            inv.error = f"version pin violated: wanted {pinned}, found {inv.version}"
        return inv
