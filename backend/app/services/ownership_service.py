"""
Domain ownership verification via DMARC RUA / TLS-RPT reporting address.

Proof logic:
  A tenant proves they control a domain by publishing our reporting slug
  in one of two DNS records:
    1. _dmarc.<domain> TXT  — rua= or ruf= contains mailto:<slug>@<reporting_domain>
    2. _smtp._tls.<domain> TXT — rua= contains mailto:<slug>@<reporting_domain>

Either is sufficient. This piggybacks on the same DNS records the user
already needs to configure for monitoring — no extra step required.
"""
from __future__ import annotations

import re

import dns.exception

from app.services.dns_resolver import resolver as _resolver
from app.services.reporting_address import reporting_address


async def _resolve_txt(name: str) -> list[str]:
    try:
        answers = await _resolver.resolve(name, "TXT")
        return [
            "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
            for r in answers
        ]
    except Exception:
        return []


def _slug_in_record(record: str, slug: str, reporting_domain: str) -> bool:
    """Return True if the record contains mailto:<slug>@<reporting_domain>."""
    target = f"mailto:{slug}@{reporting_domain}"
    # Case-insensitive, whitespace-tolerant search
    return target.lower() in record.lower().replace(" ", "")


async def check_ownership(domain_name: str, slug: str, reporting_domain: str) -> dict:
    """
    Check whether the tenant has proven domain ownership by publishing
    our reporting address in their DMARC RUA or TLS-RPT record.

    Returns:
        {
            "verified": bool,
            "method": "dmarc_rua" | "tlsrpt_rua" | None,
            "record_found": str | None,   # the matching record
            "error": str | None,
        }
    """
    # ── Check DMARC RUA ───────────────────────────────────────────────────────
    dmarc_txts = await _resolve_txt(f"_dmarc.{domain_name}")
    for txt in dmarc_txts:
        if txt.startswith("v=DMARC1") and _slug_in_record(txt, slug, reporting_domain):
            return {
                "verified": True,
                "method": "dmarc_rua",
                "record_found": txt,
                "error": None,
            }

    # ── Check TLS-RPT RUA ─────────────────────────────────────────────────────
    tlsrpt_txts = await _resolve_txt(f"_smtp._tls.{domain_name}")
    for txt in tlsrpt_txts:
        if "v=TLSRPTv1" in txt and _slug_in_record(txt, slug, reporting_domain):
            return {
                "verified": True,
                "method": "tlsrpt_rua",
                "record_found": txt,
                "error": None,
            }

    return {
        "verified": False,
        "method": None,
        "record_found": None,
        "error": None,
    }
