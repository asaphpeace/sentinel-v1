"""
Unit tests for the Concept Cards knowledge layer (PAIN_POINT_RESOLUTION_PLAN.md
Pain 2). Pure data + template rendering, no DB, no LLM.
"""
from app.knowledge.concepts import render_concept, CONCEPTS


def test_all_four_named_training_concepts_exist():
    """Alignment, compliance, authentication, return-path — the exact terms
    named as the original training-call pain points."""
    assert "dmarc.alignment" in CONCEPTS
    assert "dmarc.compliance" in CONCEPTS
    assert "dmarc.authentication_overview" in CONCEPTS
    assert "dmarc.return_path" in CONCEPTS


def test_render_concept_substitutes_context_values():
    result = render_concept("dmarc.compliance", {"compliance_pct": 88})
    assert "88" in result["text"]


def test_render_concept_falls_back_to_learn_more_on_missing_key():
    result = render_concept("dmarc.compliance", {})
    assert result["text"] == result["learn_more"]
    assert "{" not in result["text"]  # never shows a raw unfilled placeholder


def test_render_concept_unknown_id_does_not_raise():
    result = render_concept("not.a.real.concept")
    assert "term" in result and "text" in result


def test_return_path_concept_mentions_return_path_explicitly():
    """Admins used 'return-path' as the working term in the original
    training calls — the label must say it, not just 'envelope-from'."""
    assert "return-path" in CONCEPTS["dmarc.return_path"].term.lower()


def test_alignment_aligned_summary_reflects_matching_domains():
    result = render_concept("dmarc.alignment", {"auth_domain": "example.com", "header_from": "example.com"})
    assert "aligned" in result["text"].lower()
    assert "don't match" not in result["text"]


def test_alignment_aligned_summary_reflects_mismatched_domains():
    result = render_concept("dmarc.alignment", {"auth_domain": "esp.com", "header_from": "example.com"})
    assert "don't match" in result["text"]
