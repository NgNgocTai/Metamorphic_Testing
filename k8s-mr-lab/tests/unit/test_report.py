from k8s_mr_lab.report import analysis


def row(seed, mr, result, src, fu, **kw):
    base = {"seed_id": seed, "mr_id": mr, "mr_result": result, "pair_status": "VALID_PAIR", "source_sha256": src,
            "followup_sha256": fu, "gen_ms": 10, "scan_ms": 100, "elapsed_ms": 120, "cache_hits": 0,
            "scanner_invocations": 2, "skip_reason": "", "inconclusive_reason": ""}
    return {**base, **kw}


def test_identical_seeds_are_not_counted_twice():
    rows = [row("a", "MR-02", "VIOLATION", "s1", "f1"),
            row("a-copy", "MR-02", "VIOLATION", "s1", "f1", cache_hits=2, scanner_invocations=0, scan_ms=0),   # same texts
            row("b", "MR-02", "VIOLATION", "s2", "f2"),
            row("c", "MR-02", "PASS", "s3", "f3"),
            row("d", "MR-05", "SKIP", "", "", pair_status="", skip_reason="no_role"),
            row("bad", "*", "INVALID_SOURCE", "", "", pair_status="")]
    a = analysis(rows)
    d = a["dedup"]
    assert d["mr_violations (rows)"] == 3 and d["unique_pairs_with_violation"] == 2
    assert d["pairs_scanned (rows)"] == 4 and d["unique_pairs_scanned"] == 3
    assert d["seeds_with_identical_source"] == [["a", "a-copy"]]
    assert d["invalid_sources"] == 1 and a["rows_not_executed"]["SKIP"] == {"no_role": 1}
    assert d["confirmed_defects"] == 0                       # never inferred by the report


def test_cache_hits_cost_no_scanner_time():
    rows = [row("a", "MR-01", "PASS", "s", "f1"), row("b", "MR-01", "PASS", "s", "f2", scan_ms=0, cache_hits=1, scanner_invocations=1)]
    e = analysis(rows)["efficiency"]
    assert e["sum_scanner_ms (executed scans only)"] == 100 and e["scans_saved_by_cache"] == 1 and e["scanner_invocations_executed"] == 3
