"""
Unit tests for compose_spf_record() — the single function allowed to
produce SPF record text anywhere in the app (PAIN_POINT_RESOLUTION_PLAN.md
Pain 1's critical fix). Pure function, no DB, no network.
"""
from app.services.spf_composer import compose_spf_record, SPF_LOOKUP_LIMIT
from app.knowledge.platforms import SpfMechanism


def test_single_mechanism_produces_valid_record():
    result = compose_spf_record([SpfMechanism("include:sendgrid.net", 1)])
    assert result.record == "v=spf1 include:sendgrid.net ~all"
    assert result.total_lookups == 1
    assert result.over_limit is False


def test_multiple_platforms_merge_into_one_record():
    """This is the critical case — two platforms must end up in ONE record,
    not two competing 'add this exact record' instructions."""
    result = compose_spf_record([
        SpfMechanism("include:sendgrid.net", 1),
        SpfMechanism("include:spf.protection.outlook.com", 1),
    ])
    assert "include:sendgrid.net" in result.record
    assert "include:spf.protection.outlook.com" in result.record
    assert result.record.count("v=spf1") == 1
    assert result.total_lookups == 2


def test_duplicate_mechanism_counted_once():
    result = compose_spf_record([
        SpfMechanism("include:sendgrid.net", 1),
        SpfMechanism("include:sendgrid.net", 1),
    ])
    assert result.mechanisms == ("include:sendgrid.net",)
    assert result.total_lookups == 1


def test_order_is_stable_and_first_seen_preserved():
    result = compose_spf_record([
        SpfMechanism("include:b.com", 1),
        SpfMechanism("include:a.com", 1),
    ])
    assert result.mechanisms == ("include:b.com", "include:a.com")


def test_over_limit_flagged_with_warning():
    mechanisms = [SpfMechanism(f"include:vendor{i}.com", 1) for i in range(11)]
    result = compose_spf_record(mechanisms)
    assert result.total_lookups == 11
    assert result.over_limit is True
    assert result.near_limit is False  # over_limit and near_limit are mutually exclusive
    assert result.warnings
    assert "permanent" in result.warnings[0].lower() or "permerror" in result.warnings[0].lower() or "limit" in result.warnings[0].lower()


def test_near_limit_flagged_below_the_hard_limit():
    mechanisms = [SpfMechanism(f"include:vendor{i}.com", 1) for i in range(8)]  # 80% of 10
    result = compose_spf_record(mechanisms)
    assert result.total_lookups == 8
    assert result.over_limit is False
    assert result.near_limit is True
    assert result.warnings


def test_well_under_limit_has_no_warnings():
    result = compose_spf_record([SpfMechanism("include:sendgrid.net", 1)])
    assert result.warnings == ()


def test_custom_all_qualifier():
    result = compose_spf_record([SpfMechanism("include:sendgrid.net", 1)], all_qualifier="-all")
    assert result.record.endswith("-all")


def test_empty_mechanism_list_still_produces_a_valid_skeleton_record():
    result = compose_spf_record([])
    assert result.record == "v=spf1 ~all"
    assert result.total_lookups == 0


def test_lookup_cost_above_one_is_respected():
    """A platform whose include itself nests further lookups should be
    representable with a cost > 1, not silently treated as 1."""
    result = compose_spf_record([SpfMechanism("include:complex-vendor.com", 3)])
    assert result.total_lookups == 3


# ── Live record parsing + real recursive lookup counting ─────────────────────
# (PAIN_POINT_RESOLUTION_PLAN.md follow-up: a generic per-include guess
# isn't good enough — must fetch the domain's actual record and count
# nested lookups for real.)

import pytest
from app.services.spf_composer import (
    parse_spf_record, _is_lookup_mechanism, count_real_lookups,
)


def test_parse_spf_record_splits_mechanisms_and_all_qualifier():
    mechanisms, all_q = parse_spf_record("v=spf1 include:sendgrid.net a mx ~all")
    assert mechanisms == ["include:sendgrid.net", "a", "mx"]
    assert all_q == "~all"


def test_parse_spf_record_handles_strict_fail_qualifier():
    mechanisms, all_q = parse_spf_record("v=spf1 include:sendgrid.net -all")
    assert all_q == "-all"


def test_parse_spf_record_is_case_insensitive_on_v_spf1():
    mechanisms, all_q = parse_spf_record("V=SPF1 include:sendgrid.net ~all")
    assert mechanisms == ["include:sendgrid.net"]


def test_is_lookup_mechanism_true_for_include_a_mx_ptr_exists_redirect():
    for tok in ("include:x.com", "a", "a:x.com", "a/24", "mx", "mx:x.com", "ptr", "ptr:x.com", "exists:x.com", "redirect=x.com"):
        assert _is_lookup_mechanism(tok) is True, tok


def test_is_lookup_mechanism_false_for_all_and_ip_literals():
    for tok in ("all", "~all", "-all", "+all", "?all", "ip4:1.2.3.4", "ip6:::1"):
        assert _is_lookup_mechanism(tok) is False, tok


def test_is_lookup_mechanism_does_not_false_positive_on_all_starting_with_a():
    """'all' starts with 'a' — must not be misclassified as the 'a' mechanism."""
    assert _is_lookup_mechanism("all") is False
    assert _is_lookup_mechanism("a") is True


@pytest.mark.asyncio
async def test_count_real_lookups_counts_non_recursive_mechanisms_directly():
    total, warnings = await count_real_lookups(["a", "mx", "ptr"])
    assert total == 3
    assert warnings == []


@pytest.mark.asyncio
async def test_count_real_lookups_ignores_ip_literals_and_all():
    total, warnings = await count_real_lookups(["ip4:1.2.3.4", "ip6:::1", "all"])
    assert total == 0


@pytest.mark.asyncio
async def test_count_real_lookups_over_eleven_direct_mechanisms_exceeds_limit():
    total, _ = await count_real_lookups(["a"] * 11)
    assert total == 11
    assert total > 10  # SPF_LOOKUP_LIMIT
