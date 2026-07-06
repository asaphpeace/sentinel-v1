"""
Unit tests for _compute_parent_map() — relates a discovered/monitored
subdomain back to its parent domain on the Domains page, derived at read
time (not stored) so it stays correct regardless of how/when each domain
was added.
"""
from types import SimpleNamespace

from app.routers.domains import _compute_parent_map


def _d(id_, name):
    return SimpleNamespace(id=id_, name=name)


def test_subdomain_maps_to_parent():
    domains = [_d(1, "example.com"), _d(2, "mail.example.com")]
    result = _compute_parent_map(domains)
    assert result[1] is None
    assert result[2] == "example.com"


def test_unrelated_domains_have_no_parent():
    domains = [_d(1, "example.com"), _d(2, "other.com")]
    result = _compute_parent_map(domains)
    assert result[1] is None
    assert result[2] is None


def test_lookalike_domain_is_not_treated_as_parent():
    domains = [_d(1, "notexample.com"), _d(2, "mail.example.com")]
    result = _compute_parent_map(domains)
    assert result[2] is None


def test_most_specific_parent_wins_when_multiple_match():
    domains = [_d(1, "example.com"), _d(2, "eu.example.com"), _d(3, "mail.eu.example.com")]
    result = _compute_parent_map(domains)
    assert result[3] == "eu.example.com"  # not "example.com" — the closer parent
    assert result[2] == "example.com"
    assert result[1] is None
