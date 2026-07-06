"""
Unit tests for the grounded knowledge layer (app/knowledge/). Pure data +
rule-based selection, no LLM, no DB — same testing posture as
recommendation_engine.py.
"""
from app.knowledge import ALL_FACTS, select_facts, format_facts_block, get_fact


def test_no_duplicate_fact_ids():
    ids = [f.id for f in ALL_FACTS]
    assert len(ids) == len(set(ids))


def test_every_fact_has_a_namespaced_id():
    """ids look like 'dmarc.tree_walk' — namespace.name, so citations are unambiguous."""
    for f in ALL_FACTS:
        assert "." in f.id, f"{f.id} is not namespaced"


def test_get_fact_returns_known_fact():
    fact = get_fact("dmarc.tree_walk")
    assert fact is not None
    assert "tree-walk" in fact.statement.lower() or "tree" in fact.statement.lower()


def test_get_fact_returns_none_for_unknown_id():
    assert get_fact("nonexistent.fact") is None


def test_select_facts_includes_screen_defaults_even_with_no_keyword_match():
    facts = select_facts("dmarc", "hello")
    ids = [f.id for f in facts]
    assert "dmarc.tree_walk" in ids


def test_select_facts_matches_keyword_trigger():
    facts = select_facts("dmarc", "why does my SPF record exceed the lookup limit?")
    ids = [f.id for f in facts]
    assert "dmarc.spf_lookup_limit" in ids


def test_select_facts_respects_max_facts():
    facts = select_facts("dmarc", "spf dkim align reject quarantine subdomain envelope", max_facts=2)
    assert len(facts) <= 2


def test_select_facts_never_duplicates_a_fact():
    facts = select_facts("dmarc", "subdomain subdomain subdomain tree tree")
    ids = [f.id for f in facts]
    assert len(ids) == len(set(ids))


def test_format_facts_block_includes_citation_id_and_rfc():
    facts = select_facts("dmarc", "tree walk subdomain")
    block = format_facts_block(facts)
    assert "(dmarc.tree_walk)" in block
    assert "RFC 7489" in block


def test_format_facts_block_empty_for_no_facts():
    assert format_facts_block([]) == ""
