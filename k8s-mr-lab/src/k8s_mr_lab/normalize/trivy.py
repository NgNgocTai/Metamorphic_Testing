"""Trivy `config --include-non-failures` report -> NormalizedReport.

Facts verified on the pinned version (tests/golden):
  * a FAIL entry carries only StartLine/EndLine, so it is attributed to a resource by mapping the line onto the
    spans of the exact file that was scanned;
  * PASS entries are NOT resource-attributed (2 Pods -> 1 PASS entry) and are file-level: adding any unrelated object
    (ServiceAccount, RoleBinding, Pod) to a file whose only Role already FAILs KSV-0113 creates a PASS entry for it
    (probe described in docs/HUONG_DAN_TU_KIEM_TRA.md, section C). A resource is therefore "PASS" only as *absence of an
    attributed FAIL* while the check is known to have run: its kind is in the check's `kinds`, the check has a PASS
    entry, and no FAIL is attributed to it. This is NOT proof the check evaluated that resource; relations that rest
    on it are really comparisons of FAIL sets. The evidence string says so.
"""
from __future__ import annotations

from collections import Counter

from ..bundles import ConfigBundle, Span, obj_key
from ..model import FAIL, NOT_EVALUATED, PASS, NormalizedReport, ResKey


def _resource_at(line: int | None, spans: list[Span]) -> ResKey | None:
    if line is None:
        return None
    for s in spans:
        if s.start <= line <= s.end:
            return s.key
    return None


def normalize(raw: dict, bundle: ConfigBundle, spans: list[Span], control_kinds: dict[str, list[str]]) -> NormalizedReport:
    rep = NormalizedReport("trivy")
    passes: Counter[str] = Counter()
    failed: dict[str, set[ResKey]] = {}
    for result in raw.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            cid, status = m.get("ID", ""), m.get("Status", "")
            if status == "PASS":
                passes[cid] += 1
            elif status == "FAIL":
                line = (m.get("CauseMetadata") or {}).get("StartLine")
                key = _resource_at(line, spans)
                if key is None:
                    rep.unattributed_failures.append((cid, f"StartLine={line} not inside any scanned object"))
                    continue
                failed.setdefault(cid, set()).add(key)
                rep.add(cid, key, FAIL, f"line={line}", m.get("Message", ""))
            else:
                rep.notes.append(f"{cid}: unhandled status {status!r}")
    for cid, kinds in control_kinds.items():
        for o in bundle.objects:
            key = obj_key(o)
            if key[1] not in kinds or key in failed.get(cid, set()):
                continue
            if passes[cid] >= 1:
                rep.add(cid, key, PASS, "pass_inferred: no FAIL attributed to this resource while the check has a (file-level) PASS entry; absence of FAIL, not proof of evaluation")
            else:
                rep.add(cid, key, NOT_EVALUATED, "check has no PASS entry in the report")
    return rep
