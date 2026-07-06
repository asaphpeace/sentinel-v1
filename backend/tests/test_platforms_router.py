"""
Unit tests for app/routers/platforms.py's pure helper logic — the
deployment-mode resolution for Mimecast specifically, since that's the
one platform that can't be looked up as a flat key.
"""
from app.routers.platforms import _resolve_profile


def test_resolve_plain_platform_key():
    profile = _resolve_profile("sendgrid")
    assert profile is not None
    assert profile.key == "sendgrid"


def test_resolve_mimecast_direct_branch():
    profile = _resolve_profile("mimecast_direct")
    assert profile is not None
    assert profile.dkim is not None  # direct-send branch signs mail itself


def test_resolve_mimecast_relay_branch():
    profile = _resolve_profile("mimecast_relay")
    assert profile is not None
    assert profile.dkim is None  # relay branch — signing usually stays with the origin server


def test_resolve_unknown_key_returns_none():
    assert _resolve_profile("not_a_real_platform") is None


def test_resolve_bare_mimecast_returns_none():
    """Mimecast must never resolve without a branch — that's the whole point
    of forcing the deployment-mode choice in the UI."""
    assert _resolve_profile("mimecast") is None
