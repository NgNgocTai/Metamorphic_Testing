"""Evidence integrity: sha256 in every manifest.json is checked against the RAW BYTES on disk; nothing is ever auto-fixed."""
from __future__ import annotations

import hashlib
import importlib.util
import json

from conftest import ROOT

spec = importlib.util.spec_from_file_location("verify_evidence", ROOT / "scripts" / "verify_evidence.py")
ve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ve)


def test_committed_evidence_matches_its_manifests_byte_for_byte():
    n, bad = ve.verify(ROOT / "docs" / "evidence")
    assert n > 0 and bad == []


def test_a_line_ending_conversion_is_detected_and_reported_not_fixed(tmp_path):
    raw = b"a,b\r\n1,2\r\n"
    (tmp_path / "x.csv").write_bytes(raw.replace(b"\r\n", b"\n"))          # what a newline-converting checkout would leave
    (tmp_path / "manifest.json").write_text(json.dumps({"files": {"x.csv": {"sha256": hashlib.sha256(raw).hexdigest()}}}), encoding="utf-8")
    n, bad = ve.verify(tmp_path)
    assert n == 1 and bad == [(str(tmp_path), "x.csv", "line-ending")]
    assert (tmp_path / "x.csv").read_bytes() == raw.replace(b"\r\n", b"\n")      # untouched
    (tmp_path / "x.csv").write_bytes(b"other")
    assert ve.verify(tmp_path)[1][0][2] == "content"
    (tmp_path / "x.csv").unlink()
    assert ve.verify(tmp_path)[1][0][2] == "missing"


def test_evidence_is_never_newline_converted_by_git():
    attrs = (ROOT.parent / ".gitattributes").read_text(encoding="utf-8")
    assert "k8s-mr-lab/docs/evidence/** -text" in attrs
