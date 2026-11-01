"""Make a PUBLIC copy of an evidence tree without personal or machine-specific paths, and keep the link to the originals.

    python scripts/sanitize_evidence.py docs/evidence docs/evidence_public

The originals are never modified (their manifest.json hashes stay valid). The copy replaces only the strings listed in
RULES, in text files only; every other file is copied byte for byte. OUT_DIR/SANITIZATION.json records, per file, the sha256
of the original, the sha256 of the copy and the number of replacements, so a reader can go from a public file to its original.
A manifest.json inside a copied evidence directory is the ORIGINAL manifest: its hashes describe the originals, not the copy.
Run `--check DIR` to scan any tree for the patterns.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

# (name, regex, replacement). Backslashes may appear doubled inside JSON strings, hence the `\\{1,2}` groups.
RULES = [
    ("linux-home-user", re.compile(r"/home/(?!USER\b)[A-Za-z0-9_][A-Za-z0-9_.-]*"), "/home/USER"),
    ("wsl-windows-repo", re.compile(r"/mnt/[a-z]/Code/KLTN/[A-Za-z0-9_./-]*?(?=k8s-mr-lab|\b)k8s-mr-lab"), "<REPO>"),
    ("windows-project-path", re.compile(r"[A-Za-z]:\\{1,2}Code\\{1,2}KLTN(?:\\{1,2}[A-Za-z0-9_.-]+)*"), "<WINDOWS_PROJECT_PATH>"),
    ("windows-user-profile", re.compile(r"[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9_.-]+"), "<WINDOWS_USER_PROFILE>"),
]
TEXT_SUFFIXES = {".json", ".csv", ".txt", ".md", ".yaml", ".yml", ".patch", ".sh"}
CHECK_PATTERN = re.compile("|".join(f"(?:{r.pattern})" for _, r, _ in RULES))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sanitize_text(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for name, rx, rep in RULES:
        text, n = rx.subn(rep, text)
        if n:
            counts[name] = n
    return text, counts


def sanitize_tree(src: Path, out: Path) -> dict:
    if out.exists():
        raise SystemExit(f"{out} exists: refusing to overwrite")
    record: dict = {"source_root": src.name, "rules": [{"name": n, "pattern": r.pattern, "replacement": rep} for n, r, rep in RULES],
                    "files": {}}
    for f in sorted(p for p in src.rglob("*") if p.is_file()):
        rel = f.relative_to(src).as_posix()
        data = f.read_bytes()
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        new, counts = data, {}
        if f.suffix.lower() in TEXT_SUFFIXES:
            try:
                text, counts = sanitize_text(data.decode("utf-8"))
                new = text.encode("utf-8")
            except UnicodeDecodeError:
                counts = {}
        target.write_bytes(new)
        record["files"][rel] = {"original_sha256": sha(data), "sanitized_sha256": sha(new), "replacements": counts}
    (out / "SANITIZATION.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def scan(root: Path) -> list[tuple[str, str]]:
    hits = []
    for f in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES):
        for m in CHECK_PATTERN.finditer(f.read_text(encoding="utf-8", errors="replace")):
            hits.append((f.relative_to(root).as_posix(), m.group(0)))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--check", metavar="DIR", help="only scan DIR for the patterns; exit 1 if any is found")
    a = ap.parse_args(argv)
    if a.check:
        hits = scan(Path(a.check))
        for f, h in hits[:20]:
            print(f"{f}: {h}")
        print(f"{len(hits)} hit(s)")
        return 1 if hits else 0
    if not (a.src and a.out):
        ap.error("src and out are required")
    rec = sanitize_tree(Path(a.src), Path(a.out))
    changed = {k: v for k, v in rec["files"].items() if v["replacements"]}
    print(f"{len(rec['files'])} file(s) copied, {len(changed)} changed, "
          f"{sum(sum(v['replacements'].values()) for v in changed.values())} replacement(s)")
    remaining = scan(Path(a.out))
    print(f"remaining hits in the copy: {len(remaining)}")
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
