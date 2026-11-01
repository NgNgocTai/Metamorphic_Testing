"""Behavioural fingerprint of every MR on every seed: applicability, parameters, follow-up text hash, pair
validation, scan targets and trace. Used to prove that a refactor changed no MR semantics:

    python scripts/snapshot_mr_behavior.py out.json      # then diff two snapshots byte for byte
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k8s_mr_lab.bundles import BundleError, load_bundle  # noqa: E402
from k8s_mr_lab.registry import PolicyMapping, load_catalog  # noqa: E402


def snapshot() -> dict:
    catalog = load_catalog(ROOT / "mrs" / "catalog.yaml")
    mapping = PolicyMapping.load(ROOT / "config" / "policy-mapping.yaml")
    out: dict = {"mrs": sorted(catalog), "seeds": {}}
    seed_dirs = sorted(d for root in ("synthetic", "historical") for d in (ROOT / "seeds" / root).iterdir() if d.is_dir())
    for sd in seed_dirs:
        try:
            src = load_bundle(sd, sd.name)
        except BundleError as e:
            out["seeds"][sd.name] = {"load_error": str(e)}
            continue
        per_mr = {}
        for mr_id, mr in sorted(catalog.items()):
            ok, why = mr.applicable(src)
            rec: dict = {"applicable": ok, "why": why, "relation": mr.relation, "all_failures": mr.all_failures,
                         "mapped": {s: [(e.control, e.target) for e in mapping.entries(mr_id, s)] for s in ("trivy", "kubescape")},
                         "cases": []}
            if ok:
                for params in mr.generate_parameters(src, 50):
                    fu, trace = mr.transform(src, params)
                    rec["cases"].append({
                        "params": params, "trace": trace, "pair": list(mr.validate_pair(src, fu, params)),
                        "followup_sha": hashlib.sha256(fu.dump().encode()).hexdigest(),
                        "targets": {k: [list(x) for x in v] for k, v in sorted(mr.targets(src, params).items())}})
            per_mr[mr_id] = rec
        out["seeds"][sd.name] = {"source_sha": hashlib.sha256(src.dump().encode()).hexdigest(), "mrs": per_mr}
    return out


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(json.dumps(snapshot(), indent=1, sort_keys=True, default=str), encoding="utf-8")
