"""
Unit tests for the pure registrar-matching logic — no DNS resolution, no I/O.
"""
from app.services.registrar_service import _match_registrar, _GENERIC_FALLBACK


def test_matches_afrihost():
    r = _match_registrar(["ns1.afrihost.co.za", "ns2.afrihost.co.za"])
    assert r.key == "afrihost"


def test_matches_xneelo():
    r = _match_registrar(["ns1.xneelo.co.za", "ns2.xneelo.co.za"])
    assert r.key == "xneelo"


def test_matches_cloudflare():
    r = _match_registrar(["ana.ns.cloudflare.com", "bob.ns.cloudflare.com"])
    assert r.key == "cloudflare"


def test_matches_cpanel_shared_hosting():
    r = _match_registrar(["ns1.somehost.cpanel.net"])
    assert r.key == "cpanel"


def test_unknown_nameservers_fall_back_to_generic():
    r = _match_registrar(["ns1.totallyunknownprovider.xyz"])
    assert r is _GENERIC_FALLBACK


def test_empty_nameservers_fall_back_to_generic():
    assert _match_registrar([]) is _GENERIC_FALLBACK


def test_every_curated_registrar_has_steps_and_a_key():
    """Catches a copy-paste mistake (empty steps, duplicate key) before it ships."""
    from app.services.registrar_service import _REGISTRARS
    keys = set()
    for _, instructions in _REGISTRARS:
        assert instructions.steps, f"{instructions.key} has no steps"
        assert instructions.key not in keys, f"duplicate key {instructions.key}"
        keys.add(instructions.key)
