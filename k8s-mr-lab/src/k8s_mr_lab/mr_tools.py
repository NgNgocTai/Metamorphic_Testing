"""Authoring tools around the MR catalog: `mr list | validate | trace | scaffold`.

`validate` is a STRUCTURAL gate: schema and traceability are necessary, never sufficient. It also executes every MR on every
valid seed and checks the structural contract (source untouched, deterministic transform, valid pair, mapped targets exist).
It does not prove the MR is semantically valid; that is the manual review in docs/MR_SEMANTIC_REVIEW_CHECKLIST.md.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from .bundles import BundleError, load_bundle
from .checker import ALL_OF_KIND, RELATIONS, SCOPE_RULES
from .registry import MR_ID, PolicyMapping, load_catalog, read_specs
from .transforms.base import IMPLEMENTATIONS, MetamorphicRelation
from .validation import validate_source

PROPERTY_REQUIRED = ("id", "name", "domain", "security_meaning", "k8s_objects", "statement", "k8s_spec",
                     "candidate_patterns", "rationale", "review_status")
REVIEW_STATUSES = ("draft", "author_reviewed", "independently_reviewed")
PATTERN_REQUIRED = ("id", "name", "intent", "allowed_relations", "pair_validation", "shared_code", "proof_obligation")
REF_LISTS = ("owasp_k8s_2025", "cwe", "cis_nsa", "k8s_spec")


def _load(path: str | Path, key: str) -> list[dict]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))[key]


def load_properties(path: str | Path) -> list[dict]:
    return _load(path, "properties")


def load_patterns(path: str | Path) -> list[dict]:
    return _load(path, "patterns")


def load_template_elements(path: str | Path) -> dict[str, dict[str, str]]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")).get("template_elements") or {}


DERIVED_ELEMENTS = {"P-VERDICT"}           # never declared: computed by template_row
OUTPUT_ELEMENT = {"equal": "O-EQUAL", "pass_to_fail": "O-PASS-TO-FAIL", "fail_to_pass": "O-FAIL-TO-PASS"}


def template_row(spec: dict) -> set[str]:
    """All template elements of one MR: the declared ones plus those derived from relation / all_failures."""
    row = set(spec["template"]["preconditions"]) | set(spec["template"]["followup"])
    if spec["relation"] in ("pass_to_fail", "fail_to_pass"):
        row.add("P-VERDICT")
    row.add("S-ALL" if spec.get("all_failures") else "S-TARGET")
    row.add(OUTPUT_ELEMENT.get(spec["relation"], f"O-{spec['relation'].upper()}"))
    return row


def check_template(specs: list[dict], elements: dict[str, dict[str, str]]) -> list[str]:
    bad: list[str] = []
    for s in specs:
        for section in ("preconditions", "followup"):
            known = set((elements.get(section) or {})) - DERIVED_ELEMENTS
            for e in s["template"][section]:
                if e in DERIVED_ELEMENTS:
                    bad.append(f"{s['id']}: template element {e} is derived from the relation and must not be declared")
                elif e not in known:
                    bad.append(f"{s['id']}: unknown template {section} element {e} (known: {sorted(known)})")
    return bad


WORKLOAD_GROUP = "workload"          # `touches` may name a kind or this group (= the kinds of the mapping target `workload`)
SCANNERS = ("trivy", "kubescape")


def _expand(kinds: list[str], mapping: PolicyMapping) -> set[str]:
    out: set[str] = set()
    for k in kinds:
        out |= set(mapping.target_kinds(WORKLOAD_GROUP) or []) if k == WORKLOAD_GROUP else {k}
    return out


def check_mapping(specs: list[dict], mapping: PolicyMapping) -> list[str]:
    """Static validation of MR -> control -> scope, against the catalog and the control registry. The same rules apply to every MR.

    * no orphan: every mapped MR / control / target exists; every registry control is mapped; every (MR, scanner) is either mapped
      or listed under `unsupported` with a reason (never both, never neither)
    * target strategy: a target is in the vocabulary AND declared by the MR in the catalog; ALL_OF_KIND only for a rewrite of every object
    * role: `property` must be able to observe the change (control registry `reads` / `scope` x the MR's `touches`);
      `control` (negative control) must NOT be able to, otherwise it is a property comparison mislabelled"""
    bad: list[str] = []
    by_id = {s["id"]: s for s in specs}
    vocab = mapping.data.get("targets") or {}
    for t, d in vocab.items():
        if not (isinstance(d.get("kinds"), list) and d["kinds"]):
            bad.append(f"mapping: target '{t}' needs a non-empty 'kinds' list")
    mrs = mapping.data.get("mrs") or {}
    unsupported = mapping.data.get("unsupported") or {}
    for m in list(mrs) + list(unsupported):
        if m not in by_id:
            bad.append(f"mapping lists unknown MR {m}")
    registry = mapping.registry_controls()
    used: dict[str, set[str]] = {sc: set() for sc in SCANNERS}
    for mr_id, s in by_id.items():
        declared, touches = set(s["targets"]), s["touches"]
        for t in declared - set(vocab) - {ALL_OF_KIND}:
            bad.append(f"{mr_id}: catalog target '{t}' is not in the mapping target vocabulary {sorted(vocab)}")
        if (touches == ["*"]) != (declared == {ALL_OF_KIND}):
            bad.append(f"{mr_id}: touches ['*'] and targets [ALL_OF_KIND] go together (a rewrite of every object has no narrower scope)")
        changed = None if touches == ["*"] else _expand(touches, mapping)
        for sc in SCANNERS:
            raw = ((mrs.get(mr_id) or {}).get(sc)) or []
            reason = (unsupported.get(mr_id) or {}).get(sc)
            if raw and reason:
                bad.append(f"{mr_id}/{sc}: mapped AND listed under unsupported")
            if not raw and not (isinstance(reason, str) and reason.strip()):
                bad.append(f"{mr_id}/{sc}: neither mapped nor listed under unsupported with a reason (silent gap)")
            roles: dict[str, str] = {}
            for e in raw:
                if not all(isinstance(e.get(k), str) and e[k].strip() for k in ("control", "target", "reason")):
                    bad.append(f"mapping {mr_id}/{sc}: entry needs non-empty control, target and reason: {e}")
                    continue
                c, t, role = e["control"], e["target"], e.get("role", "property")
                tag = f"{mr_id}/{sc}/{c}->{t}"
                if role not in ("property", "control"):
                    bad.append(f"{tag}: role must be property or control")
                if roles.setdefault(c, role) != role:
                    bad.append(f"{tag}: control is mapped with two different roles in the same MR/scanner")
                meta = registry.get(sc, {}).get(c)
                if meta is None:
                    bad.append(f"{tag}: control is not in control-registry.yaml (regenerate it)")
                    continue
                used[sc].add(c)
                if t != ALL_OF_KIND and t not in vocab:
                    bad.append(f"{tag}: unknown target (vocabulary: {sorted(vocab)})")
                    continue
                if t not in declared:
                    bad.append(f"{tag}: target is not declared by the MR in the catalog (targets: {sorted(declared)})")
                if t == ALL_OF_KIND:
                    if changed is not None:
                        bad.append(f"{tag}: ALL_OF_KIND is only for an MR whose touches is ['*']")
                    continue
                if not set(vocab[t]["kinds"]) & set(meta["reports_on"]):
                    bad.append(f"{tag}: control never reports on {vocab[t]['kinds']} (reports_on {meta['reports_on']}); dead entry")
                    continue
                if changed is None:
                    can_observe = True
                elif meta["scope"] == "judged_object":
                    can_observe = bool(changed & set(vocab[t]["kinds"]) & set(meta["reports_on"]))
                else:
                    can_observe = bool(changed & set(meta["reads"]))
                if role == "property" and not can_observe:
                    bad.append(f"{tag}: role property but the control cannot observe what the MR touches {touches}; "
                               f"use role control (negative control) or remove it")
                if role == "control" and can_observe:
                    bad.append(f"{tag}: role control but the control can observe what the MR touches {touches}; it is a property comparison")
    for sc in SCANNERS:
        for c, meta in (registry.get(sc) or {}).items():
            if meta.get("scope_rule") and meta["scope_rule"] not in SCOPE_RULES:
                bad.append(f"control-registry: {sc}/{c} names unknown scope_rule {meta['scope_rule']!r} (known: {sorted(SCOPE_RULES)})")
        for c in sorted(set(registry.get(sc) or {}) - used[sc]):
            bad.append(f"control-registry: {sc}/{c} is not used by any mapping entry (orphan; regenerate the registry)")
    return bad


def mapping_warnings(specs: list[dict], mapping: PolicyMapping) -> list[str]:
    """A selector an MR can resolve but no scanner mapping compares is not an error (it may be kept for future controls), but it is
    never part of the comparison scope: say so instead of letting the catalog suggest otherwise."""
    out: list[str] = []
    for s in specs:
        used = {e.target for sc in SCANNERS for e in mapping.entries(s["id"], sc)}
        for t in sorted(set(s["targets"]) - used - {ALL_OF_KIND}):
            out.append(f"{s['id']}: declared target '{t}' is resolved by the MR but compared by no mapped control (outside the comparison scope)")
    return out


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
        if p.get("review_status") not in REVIEW_STATUSES:
            bad.append(f"property {p.get('id')}: review_status must be one of {list(REVIEW_STATUSES)}")
        props[p.get("id")] = p
        for lst in REF_LISTS:
            for ref in p.get(lst) or []:
                if not isinstance(ref.get("verified"), bool):
                    bad.append(f"property {p.get('id')}: {lst} entry without boolean 'verified': {ref}")
                elif not ref["verified"] and not ref.get("basis"):
                    bad.append(f"property {p.get('id')}: unverified {lst} entry must say why in 'basis': {ref}")
                elif lst == "cis_nsa" and ref["verified"]:
                    pass            # allowed only once the standard's own document was consulted (none yet; see security_properties.yaml)
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
    bad += check_mapping(specs, mapping)
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
            got = set(mr.targets(src, params))
            if got - set(mr.spec["targets"]):
                errors.append(f"{tag}: targets() produced {sorted(got - set(mr.spec['targets']))}, not declared in the catalog")
            produced |= got
    if cases == 0:
        warnings.append(f"{mr.id}: applicable on no seed, so only unit tests exercise it")
    if cases:
        for t in sorted(set(mr.spec["targets"]) - {ALL_OF_KIND} - produced):
            warnings.append(f"{mr.id}: declared target '{t}' never produced by targets() on these seeds")
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
    problems += check_template(specs, load_template_elements(a.patterns))
    seeds = seed_paths(a.seeds)
    warnings: list[str] = mapping_warnings(specs, mapping)
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


def element_matrix(specs: list[dict], elements: dict[str, dict[str, str]]) -> tuple[list[str], dict[str, set[str]]]:
    """(ordered element columns, MR id -> element set)."""
    cols = [e for section in ("preconditions", "followup", "scope", "output") for e in (elements.get(section) or {})]
    return cols, {s["id"]: template_row(s) for s in specs}


def element_groups(rows: dict[str, set[str]]) -> list[list[str]]:
    """MRs with an identical element combination form one element-level pattern (MST-wi Sec. 8.2). Largest first."""
    by: dict[frozenset, list[str]] = {}
    for mr_id, row in rows.items():
        by.setdefault(frozenset(row), []).append(mr_id)
    return sorted((sorted(v) for v in by.values()), key=lambda g: (-len(g), g[0]))


def cmd_patterns(a, catalog_path: str) -> int:
    specs = read_specs(catalog_path)
    declared = {s["id"]: s["pattern"] for s in specs}
    cols, rows = element_matrix(specs, load_template_elements(a.patterns))
    lines = ["| MR | KP | " + " | ".join(cols) + " |", "|---|---|" + "---|" * len(cols)]
    for mr_id in sorted(rows):
        lines.append(f"| {mr_id} | {declared[mr_id]} | " + " | ".join("1" if c in rows[mr_id] else "0" for c in cols) + " |")
    groups = element_groups(rows)
    lines += ["", "Element-level patterns (MRs with an identical combination):"]
    for i, g in enumerate(groups, 1):
        lines.append(f"  EP{i}: {', '.join(g)}   declared: {', '.join(sorted({declared[m] for m in g}))}")
    lines += ["", "Declared families vs element-level patterns:"]
    for kp in sorted(set(declared.values())):
        members = sorted(m for m in declared if declared[m] == kp)
        spans = [i for i, g in enumerate(groups, 1) if set(g) & set(members)]
        verdict = "identical" if len(spans) == 1 and set(groups[spans[0] - 1]) == set(members) else "coarser than the element level"
        diff = ""
        if len(members) > 1 and verdict != "identical":
            common = set.intersection(*(rows[m] for m in members))
            diff = "; differs in " + ", ".join(sorted(set.union(*(rows[m] for m in members)) - common))
        lines.append(f"  {kp} = {', '.join(members)}: spans EP{', EP'.join(map(str, spans))} -> {verdict}{diff}")
    text = "\n".join(lines) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


NA = "NOT_AVAILABLE"


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def _read_json(d: Path, name: str):
    p = d / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _test_refs(tests_dir: Path, mr_id: str, limit: int = 12) -> list[str]:
    out: list[str] = []
    for f in sorted(tests_dir.rglob("test_*.py")):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if f'"{mr_id}"' in line:          # first mention per test file
                out.append(f"{_rel(f)}:{i}")
                break
    return out[:limit]


def cmd_explain(a, catalog: dict[str, MetamorphicRelation], mapping: PolicyMapping) -> int:
    """Explain an MR from its metadata, and optionally one saved case from its evidence. Never computes a verdict."""
    from .registry import UnknownMRError
    if a.id not in catalog:
        raise UnknownMRError(f"unknown MR id(s) ['{a.id}']; catalog has {sorted(catalog)}")
    mr = catalog[a.id]
    s = mr.spec
    prop = {p["id"]: p for p in load_properties(a.properties)}.get(s["property_id"], {})
    pat = {q["id"]: q for q in load_patterns(a.patterns)}.get(s["pattern"], {})
    cls = type(mr)
    src_file = Path(inspect.getsourcefile(cls))
    out = [f"{mr.id}  {mr.name}   [status: {s['status']}]",
           "",
           f"Security property  {prop.get('id', NA)}: {prop.get('statement', NA)}",
           f"  property sources {', '.join((r.get('url') or r.get('source', '')) + ('' if r.get('verified') else ' (unverified)') for r in prop.get('k8s_spec') or []) or NA}",
           f"  risk taxonomy    {', '.join('OWASP-K8s-2025 ' + r['id'] for r in prop.get('owasp_k8s_2025') or []) or '-'}"
           f"; CWE of the detected misconfiguration: {', '.join(r['id'] for r in prop.get('cwe') or []) or '-'}"
           "  (selects the domain; does not prove the MR)",
           f"MR pattern         {s['pattern']} {pat.get('name', NA)}; template elements: {', '.join(sorted(template_row(s)))}",
           f"Relation           {s['relation']}" + ("  (+ every FAIL seen in either report)" if s.get("all_failures") else ""),
           f"Comparison scope   {s['scope']}",
           f"Origin             {s['origin']}; requirements: {', '.join(r['id'] + ' (' + r['coverage'] + ')' for r in s['requirements']) or '-'}",
           f"Touches / targets  {', '.join(s['touches'])} / {', '.join(s['targets'])}"]
    for scanner in SCANNERS:
        entries = mapping.entries(mr.id, scanner)
        txt = ", ".join(f"{e.control} ({mapping.control_meta(scanner, e.control).get('title', '?')}) on {e.target}"
                        + (" [negative control]" if e.role == "control" else "") for e in entries)
        why = (mapping.data.get("unsupported") or {}).get(mr.id, {}).get(scanner)
        out.append(f"  {scanner:<16} {txt or ('not mapped: ' + why if why else 'not mapped')}")
    out += ["Preconditions"] + [f"  - {x}" for x in s["preconditions"]]
    out += [f"Transformation     {s['transformation']}", "Pair checks (structural, not an oracle)"] + [f"  - {x}" for x in s["pair_checks"]]
    out += [f"Semantic justif.   {prop.get('rationale', NA)}",
            f"Proof obligation   {pat.get('proof_obligation', NA)}",
            f"Counterexample     {s['counterexample']}",
            "Known limitations"] + [f"  - {x}" for x in s["limits"]]
    out += [f"Implementation     {_rel(src_file)}:{inspect.getsourcelines(cls)[1]}  class {cls.__name__}"
            f"({', '.join(b.__name__ for b in cls.__mro__[1:-1])})",
            f"Tests              {', '.join(_test_refs(Path(a.catalog).resolve().parents[1] / 'tests', mr.id)) or NA}"]
    if a.case:
        d = Path(a.case)
        if not d.is_dir():
            print(f"error: case directory {d} does not exist")
            return 2
        trace, diff, asm, prov = (_read_json(d, n) for n in ("trace.json", "diff.json", "assessment.json", "provenance.json"))
        if trace and trace.get("mr") != mr.id:
            print(f"error: {d} is a case of {trace.get('mr')}, not {mr.id}")
            return 2
        out += ["", f"CASE {d.name}"]
        for side in ("source", "followup"):
            p = d / side / "bundle.yaml"
            out.append(f"  {side:<9} input  {_rel(p) if p.exists() else NA}")
        out.append(f"  parameters      {json.dumps(trace['params']) if trace else NA}")
        out.append(f"  changes         {'' if diff is not None else NA}")
        for c in diff or []:
            what = c.get("path", "")
            vals = "" if c["op"] in ("add_object", "remove_object") else f": {c.get('old')!r} -> {c.get('new')!r}"
            out.append(f"    {c['op']} {c['object']} {what}{vals}")
        if prov:
            out.append(f"  environment     {prov.get('scanner')} {prov.get('scanner_version')} [{prov.get('scan_mode')}] "
                       f"policy {str(prov.get('policy_digest'))[:16]} mapping {prov.get('mapping_digest')}")
        else:
            out.append(f"  environment     {NA}")
        for side in ("source", "followup"):
            out.append(f"  raw {side:<9}   {_rel(d / f'scanner-{side}.json') if (d / f'scanner-{side}.json').exists() else NA}")
        if asm is None:
            out.append(f"  assessment      {NA}")
        else:
            out.append(f"  pair status     {asm.get('pair_status') or NA}")
            out.append(f"  MR result       {asm.get('result')}  ({asm.get('reason')})")
            comps = (asm.get("assessment") or {}).get("comparisons")
            if comps is None:
                out.append(f"  comparisons     {NA} (no scan comparison: the case stopped before the checker)")
            else:
                out.append("  compared keys   control  resource  source -> follow-up  outcome  [verdict basis]")
                for c in comps:
                    out.append(f"    {c['control']:<9} {c['resource']}  {c['source']} -> {c['followup']}  {c['outcome']}  [{c.get('basis', NA)}]")
        tri = _read_json(d.parent.parent, "triage.json")
        t = ((tri or {}).get("cases") or {}).get(d.name)
        out.append(f"  triage          {t.get('status') + ' family=' + str(t.get('family')) + ' known=' + str(t.get('known_issue')) if t else NA}")
        out += ["", "Reading notes: an MR PASS means the relation held, not that the scanner verdict is PASS; [inferred_pass] means",
                "'no FAIL attributed', not proof of evaluation; a VIOLATION is a candidate for triage, not a confirmed defect."]
    print("\n".join(out))
    return 0


PACKET_QUESTIONS = [
    ("Q1", "Property có đúng là điều tài liệu Kubernetes nói không? Trích dẫn khớp nguyên văn (kể cả khi tác giả đã đánh `verified`)?"),
    ("Q2", "Phép biến đổi có thật sự bảo toàn (KP1/KP2) hoặc đổi đúng một chiều (KP3) thuộc tính đó? Tìm phản ví dụ mà tác giả chưa nghĩ tới."),
    ("Q3", "Precondition có đủ chặt để mọi cặp sinh ra đều có nghĩa? Nêu một đầu vào thỏa precondition nhưng làm MR sai (nếu có)."),
    ("Q4", "Mỗi control được ánh xạ có thật sự cam kết kiểm đúng property này ở đúng phiên bản? Đọc rego/metadata chứ không chỉ tiêu đề control."),
    ("Q5", "Scope so sánh có loại trừ đúng những gì được phép đổi (ví dụ finding hợp lệ trên object vừa thêm)?"),
    ("Q6", "Các phản ví dụ có bị từ chối bởi precondition/validator (xem test)? Phản ví dụ nào chỉ con người chặn được?"),
    ("Q7", "Với mỗi scanner: so sánh có mang thông tin không (xem `mr informative`)? Có control nào bất biến theo cấu trúc?"),
    ("Q8", "Giả định `closed bundle` và giới hạn đã nêu có chấp nhận được cho kết luận đang được rút ra?"),
]


def cmd_review_packet(a, catalog: dict[str, MetamorphicRelation], mapping: PolicyMapping) -> int:
    """Write a self-contained review packet for an independent reviewer. It never records an approval: the decision is left blank."""
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_explain(SimpleNamespace(id=a.id, case=None, properties=a.properties, patterns=a.patterns, catalog=a.catalog), catalog, mapping)
    if rc:
        return rc
    spec = catalog[a.id].spec
    prop = {p["id"]: p for p in load_properties(a.properties)}[spec["property_id"]]
    lines = [f"# Review packet {a.id} `{spec['name']}`", "",
             "**Trạng thái: `PENDING_INDEPENDENT_REVIEW`**. Tác giả đã tự review (`" + prop["review_status"] + "`); đó **không** phải review độc lập.",
             "Người review độc lập phải là người khác tác giả, và điền mục 5. File này không ghi nhận bất kỳ quyết định nào.", "",
             "## 1. Hồ sơ MR (sinh tự động từ catalog, property, pattern, mapping)", "", "```text", buf.getvalue().rstrip(), "```", "",
             "## 2. Phát biểu property đầy đủ", "", f"> {prop['statement']}", "",
             "Trích dẫn nguồn: " + "; ".join(f"[{r['source']}]({r.get('url') or ''}) \"{r['claim']}\" (`verified: {r['verified']}`)" for r in prop["k8s_spec"]),
             "", f"Điều kiện giả định: {prop.get('scope_assumptions')}", f"Không tương đương đã biết: {prop.get('known_non_equivalences')}", "",
             "## 3. Bằng chứng để xem", "", f"* Case study / evidence: xem `docs/case_studies/` và `docs/evidence/` (dùng `k8s-mr-lab mr explain {a.id} --case <thư mục>`).",
             f"* Mức mang thông tin của từng so sánh: `k8s-mr-lab mr informative --run <thư mục evidence>`.",
             "* Chạy lại phần cấu trúc: `k8s-mr-lab mr validate` và `pytest tests/unit -q`.", "",
             "## 4. Câu hỏi cho người review", "", "| # | Câu hỏi | Trả lời / bằng chứng |", "|---|---|---|"]
    lines += [f"| {q} | {t} | |" for q, t in PACKET_QUESTIONS]
    lines += ["", "## 5. Quyết định (người review điền)", "",
              "| Trường | Giá trị |", "|---|---|", "| Người review | |", "| Quan hệ với tác giả | (phải là người khác) |", "| Ngày | |",
              "| Quyết định | ACCEPT / ACCEPT_WITH_CHANGES / REJECT |", "| Lý do | |", "| Phản đối còn lại | |", "| Đã đọc rego/mã control đúng phiên bản pin? | có / không |", "",
              "Sau khi điền, cập nhật `review_status` của property thành `independently_reviewed` **chỉ** khi quyết định là ACCEPT và người review ghi rõ đã trả lời Q1-Q8."]
    text = "\n".join(lines) + "\n"
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


UNCOVERED = ("DERIVABLE_NOT_IMPLEMENTED", "NOT_FEASIBLE")      # the only status a requirement file may state; the rest is derived
OWASP_GROUPS = tuple(f"K{n:02d}" for n in range(1, 11))


def load_requirements(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def requirement_links(specs: list[dict]) -> dict[str, list[dict]]:
    """requirement id -> [{mr, coverage, origin}] read from the catalog (the one place that links an MR to a requirement)."""
    out: dict[str, list[dict]] = {}
    for s in specs:
        for r in s["requirements"]:
            out.setdefault(r["id"], []).append({"mr": s["id"], "coverage": r["coverage"], "origin": s["origin"]})
    return out


def requirement_status(links: list[dict], declared: str | None) -> str:
    """COVERED (>=1 MR with full coverage) | PARTIAL | the declared uncovered status."""
    if any(x["coverage"] == "full" for x in links):
        return "COVERED"
    return "PARTIAL" if links else (declared or "UNDECLARED")


def check_requirements(data: dict, specs: list[dict], mapping: PolicyMapping) -> list[str]:
    """Consistency of requirements.yaml with the catalog; a requirement is not 'covered' unless a real MR backs it."""
    bad: list[str] = []
    seen: set[str] = set()
    reasons = set(data.get("reason_codes") or {})
    links = requirement_links(specs)
    for rid in sorted(set(links) - {r.get("id") for r in data["requirements"]}):
        bad.append(f"catalog references unknown requirement {rid} ({', '.join(x['mr'] for x in links[rid])})")
    for r in data["requirements"]:
        rid = r.get("id", "?")
        if rid in seen:
            bad.append(f"duplicate requirement id {rid}")
        seen.add(rid)
        for f in ("group", "title", "source", "quote", "owasp", "cwe", "controls"):
            if not r.get(f):
                bad.append(f"{rid}: missing {f}")
        if r.get("owasp", {}).get("id") not in OWASP_GROUPS:
            bad.append(f"{rid}: owasp id must be one of {OWASP_GROUPS}")
        if r.get("owasp", {}).get("id") != r.get("group"):
            bad.append(f"{rid}: group differs from owasp id")
        if not str(r.get("cwe", {}).get("id", "")).startswith("CWE-") or not r.get("cwe", {}).get("basis"):
            bad.append(f"{rid}: cwe needs an id CWE-n and a basis (judgement)")
        if not (r.get("source", {}).get("url") or "").startswith("https://"):
            bad.append(f"{rid}: source needs an https url")
        for f in ("status", "mr_ids", "origin"):
            if f in r:
                bad.append(f"{rid}: '{f}' is derived from the catalog (MR requirements/origin); do not state it here")
        mine = links.get(rid, [])
        un = r.get("uncovered")
        if mine and un:
            bad.append(f"{rid}: has MR(s) {[x['mr'] for x in mine]} so it must not declare 'uncovered: {un}'")
        if not mine and un not in UNCOVERED:
            bad.append(f"{rid}: no MR in the catalog, so it needs 'uncovered' in {list(UNCOVERED)}")
        if un == "NOT_FEASIBLE" and r.get("reason") not in reasons:
            bad.append(f"{rid}: NOT_FEASIBLE needs a reason in {sorted(reasons)}")
        if un == "DERIVABLE_NOT_IMPLEMENTED" and not r.get("sketch"):
            bad.append(f"{rid}: DERIVABLE_NOT_IMPLEMENTED needs a sketch")
        listed = set((r.get("controls") or {}).get("trivy") or []) | set((r.get("controls") or {}).get("kubescape") or [])
        if not set(r.get("contract_read") or []) <= listed:
            bad.append(f"{rid}: contract_read must be a subset of controls")
        for x in mine:                         # the controls an MR is mapped to for this requirement must have been listed
            for sc in SCANNERS:
                for e in mapping.entries(x["mr"], sc):
                    if e.role == "property" and e.control not in (r["controls"].get(sc) or []) and r["id"] not in ("R06",):
                        bad.append(f"{rid}: {x['mr']} is mapped to {sc}/{e.control}, not listed under the requirement")
    return bad


def cmd_requirements(a, catalog_path: str, mapping: PolicyMapping) -> int:
    data = load_requirements(a.requirements)
    specs = read_specs(catalog_path)
    ids = {s["id"] for s in specs}
    problems = check_requirements(data, specs, mapping)
    links = requirement_links(specs)
    reqs = data["requirements"]
    print(f"{'req':<4} {'grp':<4} {'status':<26} {'MR (coverage, origin)':<34} title")
    stat = {}
    for r in reqs:
        mine = links.get(r["id"], [])
        stat[r["id"]] = requirement_status(mine, r.get("uncovered"))
        txt = ", ".join(f"{x['mr']} ({x['coverage']}, {x['origin']})" for x in mine) or "-"
        print(f"{r['id']:<4} {r['group']:<4} {stat[r['id']]:<26} {txt:<34} {r['title']}")
    n = len(reqs)
    cnt = lambda st: sum(v == st for v in stat.values())
    nf = [r for r in reqs if stat[r["id"]] == "NOT_FEASIBLE"]
    print(f"\nN = {n} requirements (K01: {sum(r['group'] == 'K01' for r in reqs)}, K02: {sum(r['group'] == 'K02' for r in reqs)})")
    print(f"with a full MR: {cnt('COVERED')}/{n} | with a partial MR only: {cnt('PARTIAL')}/{n} | derivable, not implemented: "
          f"{cnt('DERIVABLE_NOT_IMPLEMENTED')}/{n} | not feasible: {len(nf)}/{n} ({', '.join(sorted({r['reason'] for r in nf}))})")
    orphans = sorted(i for i in ids if not any(x["mr"] == i for v in links.values() for x in v))
    print(f"MRs NOT attached to any of these requirements (origin sanity/empirical/semantic, or the requirement is not in this list): {', '.join(orphans)}")
    print("'covered' here means an MR exists and passes the STRUCTURAL gate; none is independently reviewed and none has independent evaluation.")
    for p in problems:
        print("ERROR:", p)
    return 1 if problems else 0


def cmd_informative(a, mapping: PolicyMapping) -> int:
    """Classify every comparison of saved runs by whether its control could observe the change (reporting only)."""
    from . import informative as inf
    rows: list[dict] = []
    for run in a.run:
        rows += inf.analyze_run(run, mapping)
    summary = inf.summarize(rows)
    print(f"{'scanner/MR':<22} {'INFORMATIVE':>11} {'WEAK':>6} {'CONTROL':>8} {'UNINFORMATIVE':>14} {'INCONCLUSIVE':>13} {'total':>6}  informative_rate")
    for grp in ("by_mr", "all"):
        for key, v in summary[grp].items():
            print(f"{key:<22} {v['INFORMATIVE']:>11} {v['WEAK']:>6} {v['CONTROL']:>8} {v['UNINFORMATIVE']:>14} {v['INCONCLUSIVE']:>13} {v['total']:>6}  {v['informative_rate']}")
        print()
    if summary["unexpected_violations"]:
        print("UNEXPECTED_VIOLATION (a control flipped though nothing it can read changed):", summary["unexpected_violations"])
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        inf.write_csv(rows, out / "informative_comparisons.csv")
        (out / "informative_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"-> {out}")
    return 0


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
    template: {{preconditions: [], followup: [TODO]}}   # element ids from mrs/patterns.yaml
    origin: TODO              # prospective | retrospective | empirical | semantic | sanity
    requirements: []          # [{{id: R0x, coverage: full|partial}}]; REQUIRED (non-empty) for prospective / retrospective
    touches: [TODO]           # kinds the transformation changes (or 'workload'); ['*'] for a rewrite of every object
    targets: [TODO]           # target selectors targets() can return (vocabulary: config/policy-mapping.yaml)
# --- config/policy-mapping.yaml: under `mrs:` add `{mr_id}:` entries {{control, target, reason}} per scanner, or
#     list the scanner under `unsupported:` with the reason. `mr validate` rejects a silent gap. ---
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
