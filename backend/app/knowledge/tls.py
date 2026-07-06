"""TLS-RPT / MTA-STS protocol facts — grounding for the AI advisor.

Distinct from tls_service.py's FAILURE_REASONS, which explains *one specific
result_type code* on *one report row*. This file is the general protocol
knowledge the advisor draws on for questions about how TLS reporting and
MTA-STS work, independent of any single failure.
"""
from __future__ import annotations

from app.knowledge import Fact

FACTS: list[Fact] = [
    Fact(
        id="tls.mta_sts_modes",
        statement=(
            "MTA-STS has three modes: 'none' disables it, 'testing' reports failures "
            "without rejecting mail, 'enforce' rejects mail from senders that can't "
            "negotiate TLS. The mode lives only in the HTTPS-hosted policy file — the "
            "DNS TXT record never carries it, it only signals the policy exists."
        ),
        rfc="RFC 8461 §3",
        triggers=("mta-sts", "testing", "enforce", "mode"),
    ),
    Fact(
        id="tls.tlsrpt_separate_from_mtasts",
        statement=(
            "TLS-RPT and MTA-STS are independent — TLS-RPT collects delivery reports, "
            "MTA-STS enforces TLS policy. You can run TLS-RPT alone to see TLS posture "
            "without enforcing anything yet, which is the safe way to observe before "
            "committing to enforce mode."
        ),
        rfc="RFC 8460 §1",
        triggers=("tls-rpt", "tlsrpt", "smtp tls"),
    ),
    Fact(
        id="tls.starttls_opportunistic",
        statement=(
            "Without MTA-STS or DANE, STARTTLS is opportunistic — a sender that fails "
            "to negotiate TLS just falls back to plaintext silently, with no report and "
            "no rejection. MTA-STS is what turns that silent fallback into a visible, "
            "enforceable failure."
        ),
        rfc="RFC 3207",
        triggers=("starttls", "plaintext", "opportunistic", "fallback"),
    ),
    Fact(
        id="tls.policy_caching",
        statement=(
            "Senders that successfully fetch an MTA-STS policy cache it (recommended "
            "up to the policy's 'max_age', commonly days) — so a policy change or a "
            "newly published policy can take time to take effect across all senders, "
            "not just until the next mail attempt."
        ),
        rfc="RFC 8461 §5.2",
        triggers=("cache", "max_age", "propagat", "take effect", "stale"),
    ),
]
