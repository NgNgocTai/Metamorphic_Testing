import pytest

from k8s_mr_lab.bundles import BundleError, ConfigBundle, parse_documents
from k8s_mr_lab.transforms.yaml_reorder import reorder


def test_ut01_key_order_keeps_parsed_content(seed):
    b = seed("rbac-workload")
    r = ConfigBundle([reorder(o, "reverse") for o in b.objects])
    assert r.dump() != b.dump()                     # text really differs
    assert r.semantic_digest() == b.semantic_digest()  # parsed content identical
    # and re-parsing the dumped text gives the same content
    assert ConfigBundle(parse_documents(r.dump())).semantic_digest() == b.semantic_digest()


def test_ut01b_sequence_order_is_semantic(seed):
    b = seed("pod-basic")
    swapped = b.clone()
    swapped.objects[0]["spec"]["containers"].reverse()
    assert swapped.semantic_digest() != b.semantic_digest()


def test_ut02_duplicate_keys_are_rejected():
    with pytest.raises(BundleError, match="duplicate mapping key"):
        parse_documents("kind: Pod\nmetadata:\n  name: a\n  name: b\n")


def test_missing_role_dependency_is_reported(seed):
    problems = seed("invalid-missing-role").problems()
    assert any("missing dependency" in p for p in problems)


def test_valid_seeds_have_no_problems(seed):
    for name in ("rbac-basic", "rbac-workload", "rbac-secrets-reader", "pod-basic", "rbac-no-binding"):
        assert seed(name).problems() == []


def test_spans_cover_every_object_exactly(seed):
    b = seed("rbac-workload")
    text, spans = b.dump_with_spans()
    lines = text.splitlines()
    assert len(spans) == len(b.objects)
    for s, o in zip(spans, b.objects):
        assert lines[s.start - 1].startswith(("apiVersion", "kind", "metadata"))  # first line of the document
        assert s.key[3] == o["metadata"]["name"]
    assert spans[-1].end == len(lines)


def test_digest_is_stable_across_load_dump_cycles(seed):
    b = seed("rbac-workload")
    again = ConfigBundle(parse_documents(b.dump()))
    assert again.text_digest() == b.text_digest()
