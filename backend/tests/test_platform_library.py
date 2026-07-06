"""
Unit tests for the sending-platform knowledge library
(PAIN_POINT_RESOLUTION_PLAN.md Pain 1). Pure data, no DB, no network.
"""
from app.knowledge.platforms import (
    PLATFORM_PROFILES, MIMECAST_BRANCHES, get_platform,
    platform_key_for_detected_name, all_platform_keys,
)


def test_mimecast_is_not_in_the_flat_profile_list():
    """Mimecast requires a deployment-mode choice first — it must never be
    reachable as a plain key, or the UI would skip the branch question."""
    assert "mimecast" not in PLATFORM_PROFILES
    assert "mimecast_direct" not in PLATFORM_PROFILES
    assert "mimecast_relay" not in PLATFORM_PROFILES


def test_mimecast_branches_exist_and_differ():
    assert set(MIMECAST_BRANCHES.keys()) == {"direct", "relay"}
    direct, relay = MIMECAST_BRANCHES["direct"], MIMECAST_BRANCHES["relay"]
    assert direct.dkim is not None
    assert relay.dkim is None  # relay mode: signing responsibility usually sits with the origin server


def test_every_profile_has_at_least_one_spf_mechanism():
    for key, profile in PLATFORM_PROFILES.items():
        assert profile.spf, f"{key} has no SPF mechanism"


def test_every_profile_has_admin_path_steps():
    for key, profile in PLATFORM_PROFILES.items():
        assert profile.admin_path, f"{key} has no admin-path steps"


def test_no_duplicate_keys():
    keys = [p.key for p in PLATFORM_PROFILES.values()]
    assert len(keys) == len(set(keys))


def test_get_platform_returns_none_for_unknown_key():
    assert get_platform("not_a_real_platform") is None


def test_detected_name_mapping_matches_existing_classifier_output():
    """These exact strings are what verdict_service.py's _KNOWN_ESPS and
    source_classifier.py's KNOWN_ESPS actually produce — if either changes
    its naming, this mapping silently breaks, so it's worth pinning."""
    assert platform_key_for_detected_name("SendGrid") == "sendgrid"
    assert platform_key_for_detected_name("Google Workspace") == "google_workspace"
    assert platform_key_for_detected_name("Microsoft 365") == "microsoft_365"
    assert platform_key_for_detected_name("HubSpot") == "hubspot"


def test_detected_name_mapping_is_case_insensitive():
    assert platform_key_for_detected_name("SENDGRID") == "sendgrid"


def test_unmapped_detected_name_returns_none():
    assert platform_key_for_detected_name("Some Unknown ESP") is None


def test_all_platform_keys_includes_mimecast_branches_by_default():
    keys = all_platform_keys()
    assert "mimecast_direct" in keys
    assert "mimecast_relay" in keys
    assert len(keys) == len(PLATFORM_PROFILES) + 2


def test_all_platform_keys_can_exclude_mimecast():
    keys = all_platform_keys(include_mimecast_branches=False)
    assert "mimecast_direct" not in keys
    assert len(keys) == len(PLATFORM_PROFILES)
