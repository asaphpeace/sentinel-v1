"""DMARC protocol facts — grounding for the AI advisor, not the rule engine.

These are general protocol truths (cite-able, stable), distinct from
recommendation_engine.py's gates (which decide *this domain's* readiness)
and dmarc_service.py's AUTH_EXPLANATIONS (which explain *one auth result
row*). This file is what the advisor draws on when a question is about how
DMARC works in general, not about a specific number in front of the user.
"""
from __future__ import annotations

from app.knowledge import Fact

FACTS: list[Fact] = [
    Fact(
        id="dmarc.tree_walk",
        statement=(
            "A subdomain with no DMARC record of its own is evaluated against its "
            "organizational domain's record (the tree-walk). Its aggregate reports "
            "arrive at the organizational domain's rua address, not a separate one — "
            "so a subdomain's mail can be fully visible without ever being separately "
            "monitored."
        ),
        rfc="RFC 7489 §6.6.3",
        triggers=("subdomain", "sp=", "tree", "organizational domain"),
    ),
    Fact(
        id="dmarc.alignment_basic",
        statement=(
            "DMARC passes if EITHER SPF or DKIM aligns with the visible From: domain — "
            "it does not require both. 'Aligned' means the authenticated domain matches "
            "the From: domain (or its parent, under relaxed alignment)."
        ),
        rfc="RFC 7489 §3.1",
        triggers=("align", "pass", "fail", "why did", "spf", "dkim"),
    ),
    Fact(
        id="dmarc.policy_stages",
        statement=(
            "p=none monitors without acting on mail. p=quarantine routes failing mail "
            "to spam. p=reject blocks it before delivery. Advancing stages is "
            "irreversible in effect (you can't un-deliver blocked mail), so each stage "
            "should only advance once compliance is sustained, not just briefly high."
        ),
        rfc="RFC 7489 §6.3",
        triggers=("p=", "quarantine", "reject", "advance", "stage", "policy"),
    ),
    Fact(
        id="dmarc.sp_tag",
        statement=(
            "sp= sets a different policy specifically for subdomains, overriding the "
            "tree-walk default of inheriting the main p= policy. Without sp=, all "
            "subdomains inherit the organizational domain's policy."
        ),
        rfc="RFC 7489 §6.3",
        triggers=("sp=", "subdomain policy"),
    ),
    Fact(
        id="dmarc.spf_lookup_limit",
        statement=(
            "SPF records are limited to 10 DNS lookups total, including nested "
            "includes. Exceeding this causes a permerror, which most receivers treat "
            "as an SPF fail — this is a common, easy-to-miss cause of unexpected "
            "DMARC failures for domains with many third-party senders."
        ),
        rfc="RFC 7208 §4.6.4",
        triggers=("spf", "lookup", "permerror", "include:"),
    ),
    Fact(
        id="dmarc.envelope_vs_header",
        statement=(
            "SPF authenticates the envelope-from (the bounce address, often a "
            "different domain than what the recipient sees), while DKIM authenticates "
            "whatever domain signed the message. DMARC alignment compares each against "
            "the visible header-from — a forwarder changing the envelope is normal and "
            "expected, not a sign of spoofing."
        ),
        rfc="RFC 7489 §3.1",
        triggers=("envelope", "mismatch", "forward", "bounce"),
    ),
    Fact(
        id="dmarc.aggregate_granularity",
        statement=(
            "DMARC aggregate (rua) reports give per-source counts and dispositions, "
            "not per-message detail — they answer 'is this sending source failing', "
            "not 'why did this one email fail'. Per-message detail requires forensic "
            "(ruf) reports, which most receivers don't send and which carry message "
            "content samples (a privacy consideration of their own)."
        ),
        rfc="RFC 7489 §7.2-7.3",
        triggers=("this email", "this message", "specific email", "forensic", "ruf"),
    ),
]
