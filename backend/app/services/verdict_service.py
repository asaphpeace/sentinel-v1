"""
Rule-based per-IP DMARC verdict classifier.
Returns a structured verdict dict consumed by the DMARC router and serialised
into DmarcAuthDetailOut.  Designed to be swappable with an AI advisor later —
callers only depend on the returned dict shape, not on this module's internals.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Known ESP envelope domains — envelope mismatch against these is NORMAL
# (they route bounces under their own infrastructure)
# ---------------------------------------------------------------------------
_KNOWN_ESPS: dict[str, str] = {
    # Salesforce / ExactTarget / Marketing Cloud
    "salesforce.com":           "Salesforce",
    "exacttarget.com":          "Salesforce",
    "send.salesforce.com":      "Salesforce MC",
    "mc.exacttarget.com":       "Salesforce MC",
    # Mailchimp / Mandrill
    "mailchimp.com":            "Mailchimp",
    "mcsv.net":                 "Mailchimp",
    "rsgsv.net":                "Mailchimp",
    "mandrillapp.com":          "Mandrill",
    "mc.cx":                    "Mailchimp",
    # SendGrid
    "sendgrid.net":             "SendGrid",
    # Amazon SES
    "amazonses.com":            "Amazon SES",
    "email.amazonses.com":      "Amazon SES",
    # SparkPost / MessageBird
    "sparkpostmail.com":        "SparkPost",
    "sparkpost.com":            "SparkPost",
    # Mailgun
    "mailgun.org":              "Mailgun",
    "mailgun.com":              "Mailgun",
    # HubSpot
    "hubspot.com":              "HubSpot",
    "hubspotemail.net":         "HubSpot",
    # Marketo
    "marketo.com":              "Marketo",
    "mktomail.com":             "Marketo",
    # Oracle Eloqua
    "eloqua.com":               "Oracle Eloqua",
    # Constant Contact
    "constantcontact.com":      "Constant Contact",
    "ccsend.com":               "Constant Contact",
    # Klaviyo
    "klaviyo.com":              "Klaviyo",
    "klaviyomail.com":          "Klaviyo",
    # Zendesk
    "zendesk.com":              "Zendesk",
    # Postmark
    "postmarkapp.com":          "Postmark",
    # Campaign Monitor
    "cmail20.com":              "Campaign Monitor",
    "createsend.com":           "Campaign Monitor",
}


def _domain_from(addr: str | None) -> str | None:
    """Extract bare domain from an email address or return as-is."""
    if not addr:
        return None
    addr = addr.strip().lower()
    return addr.split("@")[-1] if "@" in addr else addr


def _known_esp(env_domain: str | None) -> str | None:
    """Return ESP name if env_domain matches a known ESP, else None."""
    if not env_domain:
        return None
    d = env_domain.lower()
    if d in _KNOWN_ESPS:
        return _KNOWN_ESPS[d]
    for pattern, name in _KNOWN_ESPS.items():
        if d.endswith("." + pattern):
            return name
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_verdict(
    header_from: str,
    envelope_from: str | None,
    dkim_domain: str | None,
    dkim_result: str | None,
    dkim_aligned: bool,
    spf_domain: str | None,
    spf_result: str | None,
    spf_aligned: bool,
    dmarc_result: str,
) -> dict:
    """
    Returns a dict with keys:
        verdict          str   authorized | authorized_dkim | authorized_spf |
                               esp_bounce | esp_unauth | auth_failure |
                               likely_spoof | unauth
        verdict_label    str   Short human label
        verdict_color    str   good | warn | amber | bad
        verdict_detail   str   Plain-English sentence(s)
        envelope_mismatch bool
        known_esp        str | None
    """
    hdr = (header_from or "").lower()
    env_domain = _domain_from(envelope_from)
    envelope_mismatch = bool(env_domain and env_domain != hdr)
    known_esp = _known_esp(env_domain) if envelope_mismatch else None

    # ── DMARC PASS ─────────────────────────────────────────────────────────
    if dmarc_result == "pass":
        if dkim_aligned and spf_aligned:
            return _v("authorized", "Authorized", "good",
                      f"Fully authorized — both DKIM and SPF align to {header_from}.",
                      envelope_mismatch, known_esp)
        if dkim_aligned:
            return _v("authorized_dkim", "Authorized (DKIM)", "good",
                      f"Authorized via DKIM — d={dkim_domain} aligns to {header_from}. "
                      f"SPF is not aligned; acceptable but adding SPF alignment strengthens deliverability.",
                      envelope_mismatch, known_esp)
        # spf_aligned only
        return _v("authorized_spf", "Authorized (SPF only)", "warn",
                  f"Authorized via SPF alignment only. No DKIM signature found — "
                  f"add DKIM signing to {header_from} for stronger authentication and forward-compatibility.",
                  envelope_mismatch, known_esp)

    # ── DMARC FAIL ─────────────────────────────────────────────────────────

    # Legitimate ESP with envelope routing (even without DKIM alignment,
    # the DKIM signature on the ESP's own domain confirms they sent it)
    if envelope_mismatch and known_esp:
        if dkim_domain:
            return _v("esp_bounce", f"{known_esp} — ESP routing", "warn",
                      f"Legitimate {known_esp} mail. The envelope sender ({env_domain}) differs from "
                      f"{header_from} because {known_esp} handles bounces under their own domain — "
                      f"this is expected. DKIM is signed by {dkim_domain}. "
                      f"To make DMARC pass, configure {known_esp} to sign with your domain's DKIM key.",
                      True, known_esp)
        return _v("esp_unauth", f"{known_esp} — needs DKIM setup", "amber",
                  f"Looks like {known_esp} mail but no DKIM signature was found for {header_from}. "
                  f"Configure {known_esp} to sign outbound mail with your domain's DKIM key to make DMARC pass.",
                  True, known_esp)

    # No authentication at all → spoofing
    dr = (dkim_result or "none").lower()
    sr = (spf_result or "none").lower()
    if dr in ("none", "") and sr in ("none", "fail", "permerror", "temperror", ""):
        return _v("likely_spoof", "Likely spoof", "bad",
                  f"No authentication found. The envelope sender ({env_domain or 'unknown'}) does not match "
                  f"{header_from} and no DKIM signature was applied — a hallmark of spoofing. "
                  f"Moving to p=quarantine would divert this mail to spam; p=reject would block it entirely.",
                  envelope_mismatch, known_esp)

    # DKIM signature failed (key mismatch / message tampered) — split into
    # two ranked, evidence-based hypotheses rather than one lumped sentence.
    if dr == "fail":
        hypotheses = _diagnose_dkim_failure(envelope_mismatch, known_esp, dkim_domain, header_from)
        return _v("auth_failure", "Auth failure — DKIM", "bad",
                  f"DKIM signature verification failed. {hypotheses[0]['label']} (see breakdown below).",
                  envelope_mismatch, known_esp, dkim_failure_hypotheses=hypotheses)

    # SPF passes but for wrong domain (unaligned third-party)
    if sr == "pass" and not spf_aligned:
        return _v("unauth", "Unauthorized sender", "amber",
                  f"SPF passes for {spf_domain or env_domain or 'unknown'} but that domain does not match "
                  f"{header_from}, so SPF alignment fails. This sender authenticates its own infrastructure "
                  f"but is not authorized to send as {header_from}.",
                  envelope_mismatch, known_esp)

    # Generic fallback
    return _v("unauth", "Unauthorized", "amber",
              f"This source is not authorized to send as {header_from}. "
              f"Review whether it is a legitimate sender that needs SPF/DKIM configuration, "
              f"or should be blocked once policy advances to p=reject.",
              envelope_mismatch, known_esp)


def _v(verdict: str, label: str, color: str, detail: str,
       envelope_mismatch: bool, known_esp: str | None,
       dkim_failure_hypotheses: list[dict] | None = None) -> dict:
    return {
        "verdict": verdict,
        "verdict_label": label,
        "verdict_color": color,
        "verdict_detail": detail,
        "envelope_mismatch": envelope_mismatch,
        "known_esp": known_esp,
        "dkim_failure_hypotheses": dkim_failure_hypotheses or [],
    }


def _diagnose_dkim_failure(envelope_mismatch: bool, known_esp: str | None, dkim_domain: str | None, header_from: str) -> list[dict]:
    """
    PAIN_POINT_RESOLUTION_PLAN.md Pain 3 — "signature invalidated in
    transit" and "key/selector mismatch" used to be lumped into one
    sentence, when they have different fixes (a forwarder modifying the
    message is often unfixable from the sending side; a rotated key is a
    five-minute DNS fix). Ranked by the only evidence actually
    available — an envelope mismatch is forwarding/mailing-list behaviour's
    hallmark, so its presence shifts the ranking, but neither hypothesis is
    ever claimed as certain, since the raw cryptographic material to prove
    it isn't part of an aggregate report.
    """
    transit = {
        "id": "transit_modification",
        "label": "Likely cause: message modified in transit",
        "confidence": 70 if envelope_mismatch else 30,
        "evidence": (
            f"The envelope sender differs from {header_from}, which is the hallmark of a forwarder or "
            f"mailing list rewriting the message after it was signed."
            if envelope_mismatch else
            "No envelope mismatch observed, so this is the less likely of the two explanations here, "
            "but still possible if a forwarder preserves the envelope."
        ),
        "explanation": (
            "A forwarder or mailing list modified the message body or headers after it was DKIM-signed, "
            "which breaks the cryptographic hash regardless of how the key is configured."
        ),
        "fix": (
            "Usually not fixable from the sending side — check whether the forwarder supports ARC "
            "sealing, which preserves an alignment-preserving authentication record across forwarding."
        ),
    }
    key_mismatch = {
        "id": "key_mismatch",
        "label": "Likely cause: DKIM key or selector mismatch",
        "confidence": 30 if envelope_mismatch else 70,
        "evidence": (
            "An envelope mismatch is present, which more often points to forwarding than a key problem, "
            "but a key mismatch can't be ruled out without checking the published key directly."
            if envelope_mismatch else
            "No envelope mismatch observed — this is the more likely explanation when sending appears direct."
        ),
        "explanation": (
            "The DKIM public key published in DNS doesn't match the private key actually used to sign — "
            "often because a key was rotated on one side but not the other."
        ),
        "fix": (
            f"Verify the public key at {dkim_domain or header_from}'s selector record matches the signing "
            f"platform's current key" + (f" — check {known_esp}'s current DKIM setup if it changed recently." if known_esp else ".")
        ),
    }
    return sorted([transit, key_mismatch], key=lambda h: -h["confidence"])
