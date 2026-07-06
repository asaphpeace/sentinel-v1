"""
B7 + B8 — Pure unit tests for DNS schema helper functions.
No database required.
"""
import pytest
from app.schemas.dns import _change_type, _is_security_alert, _extract_dmarc_policy


# ── _change_type ──────────────────────────────────────────────────────────────

def test_change_type_added():
    assert _change_type(None, "v=DMARC1; p=reject") == "added"

def test_change_type_removed():
    assert _change_type("v=DMARC1; p=reject", None) == "removed"

def test_change_type_modified():
    assert _change_type("v=DMARC1; p=none", "v=DMARC1; p=reject") == "modified"

def test_change_type_both_none():
    # Edge case: both None — treated as modified (no previous, no current is unusual but shouldn't crash)
    assert _change_type(None, None) == "added"


# ── _extract_dmarc_policy ─────────────────────────────────────────────────────

def test_extract_policy_reject():
    assert _extract_dmarc_policy("v=DMARC1; p=reject; rua=mailto:a@b.com") == "reject"

def test_extract_policy_quarantine():
    assert _extract_dmarc_policy("v=DMARC1; p=quarantine; pct=25") == "quarantine"

def test_extract_policy_none_keyword():
    assert _extract_dmarc_policy("v=DMARC1; p=none") == "none"

def test_extract_policy_empty_string():
    assert _extract_dmarc_policy("") == ""

def test_extract_policy_none_value():
    assert _extract_dmarc_policy(None) == ""

def test_extract_policy_whitespace_around_equals():
    # Real-world records sometimes have extra spaces
    assert _extract_dmarc_policy("v=DMARC1; p = reject") in ("reject", " reject")


# ── _is_security_alert ────────────────────────────────────────────────────────

class TestDmarcAlerts:
    def test_downgrade_reject_to_none(self):
        assert _is_security_alert(
            "DMARC",
            "v=DMARC1; p=reject",
            "v=DMARC1; p=none",
        ) is True

    def test_downgrade_reject_to_quarantine(self):
        assert _is_security_alert(
            "DMARC",
            "v=DMARC1; p=reject",
            "v=DMARC1; p=quarantine",
        ) is True

    def test_downgrade_quarantine_to_none(self):
        assert _is_security_alert(
            "DMARC",
            "v=DMARC1; p=quarantine",
            "v=DMARC1; p=none",
        ) is True

    def test_upgrade_not_an_alert(self):
        assert _is_security_alert(
            "DMARC",
            "v=DMARC1; p=none",
            "v=DMARC1; p=reject",
        ) is False

    def test_same_policy_not_an_alert(self):
        assert _is_security_alert(
            "DMARC",
            "v=DMARC1; p=reject; rua=mailto:old@x.com",
            "v=DMARC1; p=reject; rua=mailto:new@x.com",
        ) is False

    def test_dmarc_record_removed(self):
        assert _is_security_alert("DMARC", "v=DMARC1; p=reject", None) is True


class TestSpfAlerts:
    def test_plus_all_introduced(self):
        assert _is_security_alert(
            "SPF",
            "v=spf1 include:google.com -all",
            "v=spf1 include:google.com +all",
        ) is True

    def test_permissive_all_keyword(self):
        # " all" (no sign defaults to +all per RFC)
        assert _is_security_alert(
            "SPF",
            "v=spf1 include:google.com -all",
            "v=spf1 include:google.com all",
        ) is True

    def test_strict_all_not_alert(self):
        assert _is_security_alert(
            "SPF",
            "v=spf1 include:google.com -all",
            "v=spf1 include:google.com include:sendgrid.net -all",
        ) is False

    def test_spf_record_removed(self):
        assert _is_security_alert("SPF", "v=spf1 -all", None) is True


class TestMxAlerts:
    def test_mx_removed(self):
        assert _is_security_alert("MX", "10 mail.example.com", None) is True

    def test_mx_changed_not_alert(self):
        assert _is_security_alert("MX", "10 mail.old.com", "10 mail.new.com") is False


class TestNonCriticalRecords:
    def test_a_record_removed_not_alert(self):
        assert _is_security_alert("A", "1.2.3.4", None) is False

    def test_dkim_change_not_alert(self):
        assert _is_security_alert("DKIM", "v=DKIM1; k=rsa; p=old", "v=DKIM1; k=rsa; p=new") is False
