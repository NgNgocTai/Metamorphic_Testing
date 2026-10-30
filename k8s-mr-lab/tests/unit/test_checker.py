from k8s_mr_lab.checker import check, full_keys
from k8s_mr_lab.model import FAIL, NOT_EVALUATED, PASS, UNKNOWN, NormalizedReport
from k8s_mr_lab.triage import family_signature

K = ("", "Pod", "ns", "p")


class _MR:                      # the checker only needs relation + all_failures
    def __init__(self, relation, all_failures=False):
        self.relation, self.all_failures = relation, all_failures


def rep(status, control="C-1", key=K):
    r = NormalizedReport("x")
    if status is not None:
        r.add(control, key, status)
    return r


def run(relation, a, b):
    return check(_MR(relation), [("C-1", K)], rep(a), rep(b))


def test_equal_pass_and_violation():
    assert run("equal", PASS, PASS).result == "PASS"
    assert run("equal", FAIL, FAIL).result == "PASS"
    assert run("equal", PASS, FAIL).result == "VIOLATION"


def test_pass_to_fail():
    assert run("pass_to_fail", PASS, FAIL).result == "PASS"
    assert run("pass_to_fail", PASS, PASS).result == "VIOLATION"


def test_fail_to_pass():
    assert run("fail_to_pass", FAIL, PASS).result == "PASS"
    assert run("fail_to_pass", FAIL, FAIL).result == "VIOLATION"


def test_baseline_not_met_is_inconclusive_not_violation():
    a = run("pass_to_fail", FAIL, FAIL)         # source already FAIL: the MR precondition is not met
    assert a.result == "INCONCLUSIVE" and "baseline_precondition_not_met" in a.key_results[0].reason


def test_ut09_missing_or_unknown_verdict_never_counts_as_pass():
    for a, b in [(None, PASS), (PASS, None), (UNKNOWN, PASS), (PASS, NOT_EVALUATED), (None, None)]:
        assert run("equal", a, b).result == "INCONCLUSIVE"


def test_unattributed_failure_blocks_a_conclusion():
    r1 = rep(PASS)
    r2 = rep(PASS)
    r2.unattributed_failures.append(("C-1", "StartLine=99 not inside any scanned object"))
    assert check(_MR("equal"), [("C-1", K)], r1, r2).result == "INCONCLUSIVE"


def test_all_failures_scope_catches_a_new_failure():
    r1, r2 = rep(PASS), rep(PASS)
    r2.add("C-9", K, FAIL)
    r1.add("C-9", K, PASS)
    mr = _MR("equal", all_failures=True)
    a = check(mr, full_keys(mr, [("C-1", K)], r1, r2), r1, r2)
    assert a.result == "VIOLATION" and any(k.control == "C-9" for k in a.key_results if k.outcome == "violation")


def test_empty_scope_is_skip():
    assert check(_MR("equal"), [], rep(PASS), rep(PASS)).result == "SKIP"


def test_one_violation_wins_over_inconclusive_and_ok():
    r1, r2 = NormalizedReport("x"), NormalizedReport("x")
    r1.add("A", K, PASS); r2.add("A", K, PASS)       # ok
    r1.add("B", K, PASS); r2.add("B", K, FAIL)       # violation
    r1.add("C", K, PASS)                              # inconclusive (no follow-up verdict)
    a = check(_MR("equal"), [("A", K), ("B", K), ("C", K)], r1, r2)
    assert a.result == "VIOLATION" and a.counts() == {"ok": 1, "violation": 1, "inconclusive": 1}


def test_ut12_two_controls_with_the_same_root_cause_are_one_family():
    v = [{"control": "C-0267", "source": "PASS", "followup": "FAIL"}, {"control": "C-0272", "source": "PASS", "followup": "FAIL"}]
    assert family_signature("kubescape", "MR-02", v) == "kubescape:MR-02:PASS->FAIL"
    assert family_signature("kubescape", "MR-02", v[:1]) == family_signature("kubescape", "MR-02", v)
