"""
Unit tests for _group_by_header_from() — folds DMARC sources under the
domain that actually sent them, since a subdomain's mail is reported under
its organizational domain's rua address (DMARC tree-walk) without ever
needing to be separately monitored.
"""
from types import SimpleNamespace

from app.routers.dmarc import _group_by_header_from


def _agg(header_from, total_count=100):
    return SimpleNamespace(header_from=header_from, total_count=total_count)


def test_groups_by_header_from():
    aggs = [_agg("example.com"), _agg("mail.example.com"), _agg("example.com")]
    groups = _group_by_header_from(aggs, "example.com")
    assert set(groups.keys()) == {"example.com", "mail.example.com"}
    assert len(groups["example.com"]) == 2
    assert len(groups["mail.example.com"]) == 1


def test_missing_header_from_falls_back_to_domain_name():
    aggs = [_agg(None)]
    groups = _group_by_header_from(aggs, "example.com")
    assert "example.com" in groups


def test_header_from_is_case_and_whitespace_normalized():
    aggs = [_agg("  Mail.Example.com  ")]
    groups = _group_by_header_from(aggs, "example.com")
    assert "mail.example.com" in groups
    assert "Mail.Example.com" not in groups
