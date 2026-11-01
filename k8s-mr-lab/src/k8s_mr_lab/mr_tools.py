"""Authoring tools around the MR catalog: `mr list | validate | trace | scaffold`.

`validate` is a STRUCTURAL gate: schema and traceability are necessary, never sufficient. It also executes every MR on every
valid seed and checks the structural contract (source untouched, deterministic transform, valid pair, mapped targets exist).
It does not prove the MR is semantically valid; that is the manual review in docs/MR_SEMANTIC_REVIEW_CHECKLIST.md.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .bundles import BundleError, load_bundle
from .checker import ALL_OF_KIND, RELATIONS
from .registry import MR_ID, PolicyMapping, load_catalog, read_specs
from .transforms.base import IMPLEMENTATIONS, MetamorphicRelation
from .validation import validate_source

PROPERTY_REQUIRED = ("id", "name", "domain", "statement", "k8s_spec", "candidate_patterns", "rationale")
PATTERN_REQUIRED = ("id", "name", "intent", "allowed_relations", "pair_validation", "shared_code", "proof_obligation")
REF_LISTS = ("owasp_k8s_2025", "cwe", "cis_nsa", "k8s_spec")


def _load(path: str | Path, key: str) -> list[dict]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))[key]


def load_properties(path: str | Path) -> list[dict]:
    return _load(path, "properties")


def load_patterns(path: str | Path) -> list[dict]:
    return _load(path, "patterns")


def check_traceability(specs: list[dict], properties: list[dict], patterns: list[dict], mapping: PolicyMapping) -> list[str]:
    """Cross-file consistency of Property -> Pattern -> MR -> control mapping. Returns problems (empty = consistent)."""
    bad: list[str] = []
    props, pats = {}, {}
    for p in properties:
        miss = [f for f in PROPERTY_REQUIRED if f not in p]
        if miss:
            bad.append(f"property {p.get('id', '?')}: missing {miss}")
        if p.get("id") in props:
            bad.append(f"duplicate property id {p['id']}")
        props[p.get("id")] = p
        for lst in REF_LISTS:
            for ref in p.get(lst) or []:
                if not isinstance(ref.get("verified"), bool):
                    bad.append(f"property {p.get('id')}: {lst} entry without boolean 'verified': {ref}")
        for pid in p.get("candidate_patterns") or []:
            if pid not in {x["id"] for x in patterns}:
                bad.append(f"property {p.get('id')}: unknown pattern {pid}")
    for q in patterns:
        miss = [f for f in PATTERN_REQUIRED if f not in q]
        if miss:
            bad.append(f"pattern {q.get('id', '?')}: missing {miss}")
        if q.get("id") in pats:
            bad.append(f"duplicate pattern id {q['id']}")
        pats[q.get("id")] = q
        for r in q.get("allowed_relations") or []:
            if r not in RELATIONS:
                bad.append(f"pattern {q.get('id')}: unknown relation {r}")
    ids = {s["id"] for s in specs}
    for s in specs:
        if s["pattern"] not in pats:
            bad.append(f"{s['id']}: unknown pattern {s['pattern']}")
        elif s["relation"] not in pats[s["pattern"]]["allowed_relations"]:
            bad.append(f"{s['id']}: relation {s['relation']} not allowed by pattern {s['pattern']}")
        if s["property_id"] not in props:
            bad.append(f"{s['id']}: unknown property {s['property_id']}")
        elif s["pattern"] not in props[s["property_id"]]["candidate_patterns"]:
            bad.append(f"{s['id']}: pattern {s['pattern']} is not a candidate pattern of {s['property_id']}")
    for s in specs:
        want = (pats.get(s["pattern"]) or {}).get("base_class")
        cls = IMPLEMENTATIONS.get(s["id"])
        if want and cls and want not in {k.__name__ for k in cls.__mro__}:
            bad.append(f"{s['id']}: pattern {s['pattern']} requires base class {want}, implementation is {cls.__name__}")
    for m, per_scanner in (mapping.data.get("mrs") or {}).items():
        if m not in ids:
            bad.append(f"policy-mapping lists unknown MR {m}")
        for scanner, entries in (per_scanner or {}).items():
            for e in entries or []:
                if not all(isinstance(e.get(k), str) and e[k].strip() for k in ("control", "target")):
                    bad.append(f"policy-mapping {m}/{scanner}: entry needs non-empty 'control' and 'target': {e}")
    for scanner in ("trivy", "kubescape"):
        known = mapping.control_kinds(scanner)
        for m in ids:
            for e in ((mapping.data.get("mrs") or {}).get(m) or {}).get(scanner) or []:
                if isinstance(e.get("control"), str) and e["control"] not in known:
                    bad.append(f"{m}/{scanner}: mapped control {e['control']} is not defined under controls")
    return bad


def exercise(mr: MetamorphicRelation, seeds: list[Path], mapping: PolicyMapping) -> tuple[list[str], list[str], int]:
    """Run the MR's structural contract on every VALID seed (invalid sources are skipped, as the runner does).
    Returns (errors, warnings, cases_exercised)."""
    errors, warnings, cases = [], [], 0
    produced: set[str] = set()
    for sd in seeds:
        try:
            src = load_bundle(sd, sd.name)
        except BundleError:
            continue
        if validate_source(src):
            continue                      # INVALID_SOURCE: the runner never feeds it to an MR, so neither do we
        ok, _ = mr.applicable(src)
        if not ok:
            continue
        before = src.dump()
        for params in mr.generate_parameters(src, 50):
            cases += 1
            tag = f"{mr.id}/{sd.name}"
            fu, _ = mr.transform(src, params)
            fu2, _ = mr.transform(src, params)
            if src.dump() != before:
                errors.append(f"{tag}: transform mutated the source")
            if fu.dump() != fu2.dump():
                errors.append(f"{tag}: transform is not deterministic")
            if fu.dump() == before:
                errors.append(f"{tag}: follow-up identical to source")
            status, why = mr.validate_pair(src, fu, params)
            if status != "VALID_PAIR":
                errors.append(f"{tag}: generated pair is {status} ({why})")
            produced |= set(mr.targets(src, params))
    if cases == 0:
        warnings.append(f"{mr.id}: applicable on no seed, so only unit tests exercise it")
    for scanner in ("trivy", "kubescape"):
        for e in mapping.entries(mr.id, scanner):
            if cases and e.target != ALL_OF_KIND and e.target not in produced:
                warnings.append(f"{mr.id}/{scanner}: target '{e.target}' never produced by targets() on these seeds")
    return errors, warnings, cases


def _invalid(sd: Path) -> bool:
    try:
        return bool(validate_source(load_bundle(sd, sd.name)))
    except BundleError:
        return True


def seed_paths(roots: list[str]) -> list[Path]:
    out: list[Path] = []
    for r in map(Path, roots):
        out += sorted(d for d in r.iterdir() if d.is_dir() and (any(d.glob("*.yaml")) or any(d.glob("*.yml"))))
    return out


def cmd_list(catalog: dict[str, MetamorphicRelation], mapping: PolicyMapping) -> int:
    print(f"{'ID':6} {'STATUS':16} {'PATTERN':8} {'RELATION':13} {'PROPERTY':30} SCANNERS  NAME")
    for mr in catalog.values():
        sc = ",".join(s for s in ("trivy", "kubescape") if mapping.supports(mr.id, s)) or "-"
        print(f"{mr.id:6} {mr.spec['status']:16} {mr.pattern:8} {mr.relation:13} {mr.property_id:30} {sc:9} {mr.name}")
    return 0


def cmd_validate(a, catalog_path: str, mapping: PolicyMapping) -> int:
    specs = read_specs(catalog_path)                       # schema, duplicate ids, relation/status values
    catalog = load_catalog(catalog_path)                   # catalog <-> @implements binding
    problems = check_traceability(specs, load_properties(a.properties), load_patterns(a.patterns), mapping)
    seeds = seed_paths(a.seeds)
    warnings: list[str] = []
    for mr in catalog.values():
        try:
            errs, warns, n = exercise(mr, seeds, mapping)
        except (KeyError, TypeError) as e:           # e.g. a malformed mapping entry already reported above
            errs, warns, n = [f"{mr.id}: could not be exercised ({type(e).__name__}: {e})"], [], 0
        print(f"{mr.id:6} {mr.name:28} exercised {n:2} case(s) on {len(seeds)} seed(s)  {'OK' if not errs else 'FAIL'}")
        problems += errs
        warnings += warns
    for w in warnings:
        print(f"warning: {w}")
    for p in problems:
        print(f"ERROR: {p}")
    skipped = [sd.name for sd in seeds if _invalid(sd)]
    if skipped:
        print(f"skipped invalid seed(s) (never fed to an MR): {', '.join(skipped)}")
    print(f"\n{len(catalog)} MR(s), {len(problems)} error(s), {len(warnings)} warning(s)")
    print("STRUCTURAL gate only; it does not prove an MR is semantically valid. "
          "Complete docs/MR_SEMANTIC_REVIEW_CHECKLIST.md before relying on it.")
    return 1 if problems else 0


def cmd_trace(a, catalog_path: str, mapping: PolicyMapping) -> int:
    specs = {s["id"]: s for s in read_specs(catalog_path)}
    props = {p["id"]: p for p in load_properties(a.properties)}
    lines = ["| MR | Status | Pattern | Property | OWASP K8s 2025 | CWE (control's weakness class) | Spec refs verified | Trivy controls | Kubescape controls |",
             "|---|---|---|---|---|---|---|---|---|"]
    for mr_id, s in specs.items():
        p = props[s["property_id"]]
        owasp = ", ".join(f"{r['id']}" + ("" if r["verified"] else "?") for r in p.get("owasp_k8s_2025") or []) or "-"
        cwe = ", ".join(f"{r['id']}" + ("" if r["verified"] else " (unverified)") for r in p.get("cwe") or []) or "-"
        refs = p.get("k8s_spec") or []
        ok = f"{sum(r['verified'] for r in refs)}/{len(refs)}"
        ctl = {sc: ", ".join(sorted({e.control for e in mapping.entries(mr_id, sc)})) or "-" for sc in ("trivy", "kubescape")}
        lines.append(f"| {mr_id} | {s['status']} | {s['pattern']} | {p['id']} | {owasp} | {cwe} | {ok} | {ctl['trivy']} | {ctl['kubescape']} |")
    text = "\n".join(lines) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


SCAFFOLD_KP3 = '''"""{mr_id} — TODO one-line description (pattern {pattern}, controlled single-field change)."""
from __future__ import annotations

from ..bundles import ConfigBundle, obj_key
from ..model import ResKey
from .base import implements, key_to_list, list_to_key
from .patterns import Change, ControlledChange


@implements("{mr_id}")
class {cls}(ControlledChange):
    no_candidates_reason = "TODO_why_not_applicable"

    def candidates(self, source: ConfigBundle) -> list[dict]:
        raise NotImplementedError      # PRECONDITION: which objects may be mutated (inspect structure, not field presence)

    def candidate_params(self, candidate: dict) -> dict:
        return {{"target": key_to_list(obj_key(candidate))}}

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()                # never mutate `source`
        raise NotImplementedError          # TRANSFORMATION: apply the single change to fu

    def expected_change(self, source: ConfigBundle, params: dict) -> Change | None:
        raise NotImplementedError          # PAIR VALIDATION: Change(object, path, old, new)

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        return {{"workload": [list_to_key(params["target"])]}}   # SCOPE: names used by policy-mapping.yaml
'''

SCAFFOLD_CUSTOM = '''"""{mr_id} — TODO one-line description (pattern {pattern}, custom implementation)."""
from __future__ import annotations

from ..bundles import ConfigBundle
from ..model import ResKey
from .base import MetamorphicRelation, implements


@implements("{mr_id}")
class {cls}(MetamorphicRelation):
    def applicable(self, source: ConfigBundle) -> tuple[bool, str]:
        raise NotImplementedError          # PRECONDITION: return (False, "reason") when the source does not qualify

    def generate_parameters(self, source: ConfigBundle, max_cases: int) -> list[dict]:
        raise NotImplementedError

    def transform(self, source: ConfigBundle, params: dict) -> tuple[ConfigBundle, dict]:
        fu = source.clone()                # never mutate `source`
        raise NotImplementedError          # TRANSFORMATION

    def validate_pair(self, source: ConfigBundle, followup: ConfigBundle, params: dict) -> tuple[str, str]:
        raise NotImplementedError          # prove the follow-up differs exactly as the MR says: VALID_PAIR or INVALID_PAIR

    def targets(self, source: ConfigBundle, params: dict) -> dict[str, list[ResKey]]:
        raise NotImplementedError          # SCOPE: names used by policy-mapping.yaml
'''

SCAFFOLD_YAML = '''# --- mrs/catalog.yaml (append) ---
  - id: {mr_id}
    name: TODO-kebab-name
    category: TODO            # R-number of the semantic area
    status: candidate         # promote to mvp_conditional only after the mapping is verified on the pinned scanners
    pattern: {pattern}
    property_id: TODO         # an id from mrs/security_properties.yaml (add one first if none fits)
    property: TODO
    relation: TODO            # one of {relations}
    scope: TODO
    preconditions: [TODO]
    transformation: TODO
    pair_checks: [TODO]
    counterexample: TODO      # an input the precondition or pair check must reject
    limits: [TODO]
# --- config/policy-mapping.yaml: add `{mr_id}:` under `mrs:` once controls are verified ---
'''


def cmd_scaffold(a, catalog_path: str) -> int:
    """Write an implementation skeleton for the chosen pattern. Refuses a malformed or used id and an unknown pattern."""
    if not MR_ID.match(a.id):
        print(f"error: id '{a.id}' must look like MR-07")
        return 2
    if a.id in {s["id"] for s in read_specs(catalog_path)}:
        print(f"error: {a.id} already exists in the catalog")
        return 2
    patterns = {q["id"]: q for q in load_patterns(a.patterns)}
    if a.pattern not in patterns:
        print(f"error: unknown pattern '{a.pattern}' (known: {sorted(patterns)})")
        return 2
    template = SCAFFOLD_KP3 if patterns[a.pattern].get("base_class") == "ControlledChange" else SCAFFOLD_CUSTOM
    cls = "".join(w.capitalize() for w in a.name.replace("_", "-").split("-"))
    path = Path(a.src_dir) / f"{a.name.replace('-', '_')}.py"
    if path.exists():
        print(f"refusing to overwrite {path}")
        return 1
    path.write_text(template.format(mr_id=a.id, cls=cls, pattern=a.pattern), encoding="utf-8")
    print(f"wrote {path}")
    print("WARNING: transforms/ is imported as a whole, so until the catalog entry below is added load_catalog() fails with "
          "'implemented but missing from catalog'. Add the entry before running anything else.\n")
    print(SCAFFOLD_YAML.format(mr_id=a.id, pattern=a.pattern, relations=sorted(RELATIONS)))
    return 0
