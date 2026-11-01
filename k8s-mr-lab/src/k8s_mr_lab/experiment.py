"""Experiment provenance: everything needed to say WHICH framework, declaration, scanner and inputs produced a result.

Written into `environment.lock.json` of every run by the one `run` command. It records identities and digests, never results.
"""
from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path

from .registry import MAPPING_SCHEMA, REGISTRY_FILE

EXPERIMENT_TYPES = ("baseline", "mutation", "historical-defect")
FRAMEWORK_PATHS = ("src", "config", "mrs", "seeds", "scripts", "tests", "pyproject.toml")


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def tree_sha(dirs: list[Path]) -> str:
    """Digest over the relative path and content of every seed file (the exact seed set a run was given)."""
    h = hashlib.sha256()
    for d in sorted(dirs):
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            h.update(f"{d.name}/{f.relative_to(d).as_posix()}".encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def git_state(repo: Path) -> dict:
    """Commit, and whether the code and declarations a result depends on (not docs or run output) differ from it. `dirty` is None
    when git could not answer (a checkout on a Windows mount can take over 20 s), never a guess."""
    def run(*args: str) -> str | None:
        try:
            r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.SubprocessError):
            return None
        return r.stdout.strip() if r.returncode == 0 else None
    sha = run("rev-parse", "HEAD")
    status = run("status", "--porcelain", "--", *FRAMEWORK_PATHS) if sha else None
    return {"commit": sha, "dirty": None if status is None else bool(status)}


def provenance(*, experiment_type: str, experiment_id: str | None, scope_profile: str, catalog_path: str, mapping_path: str,
               seed_dirs: list[Path], runner, mr_ids: list[str] | None) -> dict:
    if experiment_type not in EXPERIMENT_TYPES:
        raise ValueError(f"experiment type must be one of {list(EXPERIMENT_TYPES)}")
    cat, mp = Path(catalog_path), Path(mapping_path)
    from .registry import active_mrs
    scanner, mapping = runner.scanner, runner.mapping
    policy = scanner.policy_digest()
    derived = (mapping.registry.get("derived_under") or {}).get(scanner.name)
    return {
        "experiment_id": experiment_id or runner.run_id, "experiment_type": experiment_type, "scope_profile": scope_profile,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "framework_git": git_state(Path(__file__).resolve().parents[2]),
        "schema": {"mapping": MAPPING_SCHEMA, "control_registry": mapping.registry.get("version")},
        "digests": {"catalog": file_sha(cat), "requirements": file_sha(cat.with_name("requirements.yaml")),
                    "properties": file_sha(cat.with_name("security_properties.yaml")), "patterns": file_sha(cat.with_name("patterns.yaml")),
                    "mapping": file_sha(mp), "control_registry": file_sha(mp.with_name(REGISTRY_FILE)), "mapping_and_registry": mapping.digest()},
        "registry_derived_under_policy": derived, "registry_matches_policy": derived == policy,
        "seed_digest": tree_sha(seed_dirs), "seed_count": len(seed_dirs),
        "included_mrs": [{"id": m.id, "status": m.spec["status"]} for m in active_mrs(runner.catalog, mr_ids)],
    }
