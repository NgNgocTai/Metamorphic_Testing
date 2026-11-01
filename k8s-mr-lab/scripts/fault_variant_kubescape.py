"""Build an ISOLATED copy of the pinned Kubescape artifacts with the rego of ONE control patched.

    python scripts/fault_variant_kubescape.py SRC_ARTIFACTS OUT_DIR --control C-0267 --variant namespace-fix

The pinned artifacts (~/.kubescape) are never modified. The output directory has a different policy digest, so every run on
it is a separate experiment track and must never be mixed with the pinned baseline (the runner refuses to compare
scans whose digests differ). Variants:

  namespace-fix   adds the namespace comparison the pinned rego lacks when joining a RoleBinding to a Role
                  (a hand-written fix hypothesis, NOT the upstream fix): fix-validation of a historical defect
  drop-subject-ns removes the `subjects[j].namespace == sa.metadata.namespace` check: an INJECTED fault (mutant)
  drop-watch-verb removes "watch" from `verbs := ["get", "list", "watch", "*"]` (C-0015): an INJECTED fault chosen from the text of
                  requirement R08, not from any observation of the scanner
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

NS_FIX_ANCHOR = "\trolebinding.roleRef.kind == role.kind\n"
NS_FIX_CALL = NS_FIX_ANCHOR + "\trole_in_scope(role, rolebinding)\n"
NS_FIX_HELPERS = '''
role_in_scope(role, _) if {
	role.kind == "ClusterRole"
}

role_in_scope(role, rolebinding) if {
	role.kind == "Role"
	rolebinding.kind == "RoleBinding"
	role.metadata.namespace == rolebinding.metadata.namespace
}
'''
DROP_LINE = "\trolebinding.subjects[j].namespace == sa.metadata.namespace\n"


WATCH_ANCHOR = 'verbs := ["get", "list", "watch", "*"]'
WATCH_MUTANT = 'verbs := ["get", "list", "*"]'


def patch(rule: str, variant: str) -> str:
    if variant == "namespace-fix":
        if rule.count(NS_FIX_ANCHOR) != 1:
            raise SystemExit("anchor for namespace-fix not found exactly once: the pinned rego changed")
        return rule.replace(NS_FIX_ANCHOR, NS_FIX_CALL) + NS_FIX_HELPERS
    if variant == "drop-subject-ns":
        if rule.count(DROP_LINE) != 1:
            raise SystemExit("subject namespace line not found exactly once: the pinned rego changed")
        return rule.replace(DROP_LINE, "")
    if variant == "drop-watch-verb":
        if rule.count(WATCH_ANCHOR) != 1:
            raise SystemExit("verb list not found exactly once: the pinned rego changed")
        return rule.replace(WATCH_ANCHOR, WATCH_MUTANT)
    raise SystemExit(f"unknown variant {variant}")


def patch_controls(obj: dict, control: str, variant: str) -> int:
    n = 0
    if isinstance(obj, list):                 # some artifact files are plain lists (e.g. controls-inputs.json)
        return 0
    for c in obj.get("controls", [obj]):
        if isinstance(c, dict) and c.get("controlID") == control:
            for r in c["rules"]:
                r["rule"] = patch(r["rule"], variant)
                n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--control", required=True)
    ap.add_argument("--variant", required=True, choices=["namespace-fix", "drop-subject-ns", "drop-watch-verb"])
    a = ap.parse_args(argv)
    src, out = Path(a.src), Path(a.out)
    if out.exists():
        raise SystemExit(f"{out} exists: refusing to overwrite")
    shutil.copytree(src, out)
    changed = {}
    for f in sorted(out.glob("*.json")):
        obj = json.loads(f.read_text(encoding="utf-8"))
        n = patch_controls(obj, a.control, a.variant)
        if n:
            f.write_text(json.dumps(obj), encoding="utf-8")
            changed[f.name] = n
    if not changed:
        raise SystemExit(f"control {a.control} not found in {src}")
    record = {"source": str(src), "control": a.control, "variant": a.variant, "patched_files": changed,
              "sha256": {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.glob("*.json")) if f.name in changed}}
    (out / "FAULT_VARIANT.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
