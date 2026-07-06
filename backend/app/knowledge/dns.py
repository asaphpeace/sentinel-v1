"""DNS protocol facts — grounding for the AI advisor.

General DNS knowledge that underlies the hand-holding/registrar work
(registrar_service.py) and the DNS timeline/drift-detection feature
(dns_service.py), without being specific to either.
"""
from __future__ import annotations

from app.knowledge import Fact

FACTS: list[Fact] = [
    Fact(
        id="dns.propagation_delay",
        statement=(
            "A DNS change isn't instant — it depends on the record's TTL and how "
            "aggressively resolvers cache. Most providers update within minutes to a "
            "few hours, but a long-TTL record (e.g. 24h+) can take that long to be "
            "seen everywhere, even though it's already correct at the authoritative "
            "nameserver."
        ),
        rfc="RFC 1034 §3.6.4",
        triggers=("propagat", "not showing", "still old", "ttl", "takes time"),
    ),
    Fact(
        id="dns.txt_record_limits",
        statement=(
            "A single TXT record string is limited to 255 characters per substring; "
            "DNS providers commonly auto-split, and crucially, an SPF record split "
            "into multiple separate TXT records (rather than one record auto-folded "
            "by the provider) is invalid per spec and will fail to evaluate."
        ),
        rfc="RFC 7208 §3.3",
        triggers=("txt record", "too long", "split", "255"),
    ),
    Fact(
        id="dns.axfr_refused_is_normal",
        statement=(
            "A zone transfer (AXFR) request is refused by virtually all correctly "
            "configured authoritative nameservers by default — a refusal is the "
            "expected, secure outcome, not a sign of misconfiguration."
        ),
        rfc="RFC 5936 §2.2",
        triggers=("axfr", "zone transfer"),
    ),
    Fact(
        id="dns.ct_log_coverage",
        statement=(
            "Certificate Transparency logs only ever see hostnames that had a "
            "publicly-trusted TLS certificate issued — an internal-only subdomain "
            "with no public cert, or one only ever covered by a wildcard cert, won't "
            "show up in CT-log-based discovery even though it exists."
        ),
        rfc=None,
        triggers=("ct log", "certificate transparency", "crt.sh", "didn't find"),
    ),
]
