"""Certificate / TLS chain protocol facts — grounding for the AI advisor.

General PKI/chain-validation knowledge, distinct from cert_service.py's
per-cert status/alerting logic for one specific certificate.
"""
from __future__ import annotations

from app.knowledge import Fact

FACTS: list[Fact] = [
    Fact(
        id="certs.chain_validation",
        statement=(
            "A valid certificate needs three things to be trusted: it isn't expired, "
            "its hostname matches what's being connected to (or is covered by a "
            "wildcard/SAN), and its issuing CA is in the trust store of whoever is "
            "connecting. Any one failing breaks the chain regardless of the other two."
        ),
        rfc="RFC 5280 §6",
        triggers=("chain", "trust", "valid", "expired", "hostname mismatch"),
    ),
    Fact(
        id="certs.san_vs_cn",
        statement=(
            "Modern clients validate the certificate's SAN (Subject Alternative Name) "
            "field, not the legacy CN (Common Name) — a cert with the right CN but a "
            "SAN that doesn't include the connecting hostname will still fail "
            "validation in current browsers and mail servers."
        ),
        rfc="RFC 6125 §6.4.4",
        triggers=("san", "subject alternative", "common name", "cn="),
    ),
    Fact(
        id="certs.renewal_lead_time",
        statement=(
            "Certificate renewal should happen well before expiry, not at the deadline "
            "— automated renewal (e.g. Let's Encrypt's 90-day certs auto-renewing at "
            "~60 days) is far more reliable than manual renewal, which is the most "
            "common cause of unplanned expired-certificate outages."
        ),
        rfc=None,
        triggers=("renew", "expir", "let's encrypt", "automat"),
    ),
    Fact(
        id="certs.starttls_no_hostname_check",
        statement=(
            "Opportunistic STARTTLS (without MTA-STS/DANE) traditionally skips strict "
            "hostname validation, since mail servers historically prioritized "
            "delivering mail over rejecting it — this is why an MX cert can have a "
            "hostname mismatch and still 'work' for plain SMTP while still failing "
            "MTA-STS's stricter validation."
        ),
        rfc="RFC 8461 §3.3",
        triggers=("hostname mismatch", "still works", "smtp tls"),
    ),
]
