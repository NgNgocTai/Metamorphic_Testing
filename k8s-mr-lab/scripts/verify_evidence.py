"""Verify every evidence manifest against the RAW BYTES of the files on disk. Never modifies anything.

    python scripts/verify_evidence.py [DIR ...]        (default: docs/evidence)

Exit code 1 if any file is missing or differs. A mismatch that disappears after CRLF->LF conversion is reported as
`line-ending` (a checkout converted newlines; see .gitattributes: evidence is `-text`), anything else as `content`.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def verify(root: Path) -> tuple[int, list[tuple[str, str, str]]]:
    n, bad = 0, []
    for m in sorted(root.rglob("manifest.json")):
        files = json.loads(m.read_text(encoding="utf-8")).get("files")
        if not isinstance(files, dict):
            continue
        for rel, v in files.items():
            n += 1
            f = m.parent / rel
            if not f.is_file():
                bad.append((str(m.parent), rel, "missing"))
                continue
            b = f.read_bytes()
            if hashlib.sha256(b).hexdigest() != v["sha256"]:
                as_lf = b.replace(b"\r\n", b"\n")
                lf = v["sha256"] in (hashlib.sha256(as_lf).hexdigest(), hashlib.sha256(as_lf.replace(b"\n", b"\r\n")).hexdigest())
                bad.append((str(m.parent), rel, "line-ending" if lf else "content"))
    return n, bad


def main(argv=None) -> int:
    roots = [Path(a) for a in (argv if argv is not None else sys.argv[1:])] or [Path("docs/evidence")]
    total, allbad = 0, []
    for r in roots:
        n, bad = verify(r)
        total += n
        allbad += bad
    print(f"checked {total} file hash(es), {len(allbad)} mismatch(es)")
    for d, rel, why in allbad:
        print(f"  {why:12} {d}/{rel}")
    return 1 if allbad else 0


if __name__ == "__main__":
    sys.exit(main())
