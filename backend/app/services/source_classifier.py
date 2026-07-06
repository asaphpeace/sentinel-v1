"""
Rule-based source classification with confidence scoring.
Maps (dkim_aligned, spf_aligned, dmarc_result, rdns, asn, org_name) → classification.

Classifications:
  authorized  — legitimate, fully aligned sender
  forwarded   — forwarder (SPF breaks, DKIM survives)
  unauth      — known ESP not yet aligned (fixable)
  spoof       — no auth, likely spoof
"""
from __future__ import annotations

import re

# Known ESP patterns → friendly name
KNOWN_ESPS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"google|gmail|gapps|googlemail", re.I), "Google Workspace"),
    (re.compile(r"microsoft|office365|outlook|hotmail|msn", re.I), "Microsoft 365"),
    (re.compile(r"mailchimp|mcsv\.net", re.I), "Mailchimp"),
    (re.compile(r"sendgrid", re.I), "SendGrid"),
    (re.compile(r"amazon.*ses|amazonses", re.I), "Amazon SES"),
    (re.compile(r"mailgun", re.I), "Mailgun"),
    (re.compile(r"postmark", re.I), "Postmark"),
    (re.compile(r"sparkpost|messagebird", re.I), "SparkPost"),
    (re.compile(r"hubspot", re.I), "HubSpot"),
    (re.compile(r"salesforce|exacttarget", re.I), "Salesforce"),
    (re.compile(r"zoho", re.I), "Zoho"),
    (re.compile(r"sendinblue|brevo", re.I), "Brevo"),
    (re.compile(r"constantcontact", re.I), "Constant Contact"),
    (re.compile(r"klaviyo", re.I), "Klaviyo"),
]

SPOOF_ASNS = {"9009", "29073", "51348", "206610"}  # common abuse ASNs / Tor exits

TOR_PATTERNS = re.compile(r"tor|exit|relay|anonymize", re.I)


def _match_esp(text: str) -> str | None:
    for pattern, name in KNOWN_ESPS:
        if pattern.search(text):
            return name
    return None


def classify_source(g: dict) -> dict:
    """
    g keys: dkim_aligned, spf_aligned, dkim_result, spf_result,
            rdns, asn, org_name, source_org, dkim_domain, spf_domain
    Returns: {classification, confidence, reason, label, action}
    """
    dkim_aligned: bool = g.get("dkim_aligned", False)
    spf_aligned: bool = g.get("spf_aligned", False)
    dkim_result: str = g.get("dkim_result") or "none"
    spf_result: str = g.get("spf_result") or "none"
    rdns: str = g.get("rdns") or ""
    asn: str = g.get("asn") or ""
    org_name: str = g.get("org_name") or g.get("source_org") or ""
    dkim_domain: str = g.get("dkim_domain") or ""
    header_from: str = g.get("header_from") or ""

    search_text = f"{rdns} {org_name} {dkim_domain}"
    esp_name = _match_esp(search_text)
    is_tor = bool(TOR_PATTERNS.search(rdns)) or asn in SPOOF_ASNS

    # ── Authorized ────────────────────────────────────────────────────────────
    if dkim_aligned and spf_aligned:
        return {
            "classification": "authorized",
            "confidence": 98,
            "label": "Authorized",
            "reason": "Recognized sending infrastructure — both SPF and DKIM are aligned to your domain.",
            "action": "No action needed.",
        }
    if dkim_aligned and not spf_aligned:
        return {
            "classification": "authorized",
            "confidence": 95,
            "label": "Authorized",
            "reason": "DKIM is aligned to your domain and passes. SPF is not aligned but DMARC still passes via DKIM.",
            "action": "Consider aligning SPF for belt-and-suspenders protection.",
        }
    if spf_aligned and not dkim_aligned:
        return {
            "classification": "authorized",
            "confidence": 90,
            "label": "Authorized",
            "reason": "SPF is aligned to your domain and passes. DKIM is not aligned — DMARC passes via SPF only.",
            "action": "Add DKIM signing aligned to your domain for stronger protection.",
        }

    # ── Forwarded ─────────────────────────────────────────────────────────────
    if dkim_result == "pass" and not dkim_aligned and spf_result in ("fail", "softfail", "neutral"):
        return {
            "classification": "forwarded",
            "confidence": 87,
            "label": "Forwarded mail",
            "reason": "The DKIM signature survives forwarding but SPF breaks because the forwarder changes the envelope sender. This is expected behaviour for mailing lists and auto-forwarders.",
            "action": "No action needed. ARC sealing by the forwarder would improve future pass rates.",
        }

    # ── Known ESP not yet aligned ──────────────────────────────────────────────
    if esp_name and dkim_result == "pass" and not dkim_aligned:
        return {
            "classification": "unauth",
            "confidence": 88,
            "label": "Fix alignment",
            "reason": f"{esp_name} signs your messages with its own domain (d={dkim_domain or '?'}), not {header_from}. DMARC fails because the signature isn't aligned to your From: domain.",
            "action": f"Enable branded DKIM in {esp_name}: publish the CNAME records they provide so signatures use d={header_from}.",
        }
    if esp_name and spf_result in ("fail", "softfail") and not spf_aligned:
        return {
            "classification": "unauth",
            "confidence": 80,
            "label": "Fix alignment",
            "reason": f"{esp_name} is sending on your behalf but its envelope sender domain doesn't match {header_from}, so SPF isn't aligned. DKIM may also be missing.",
            "action": f"Configure {esp_name} with your domain's SPF and/or enable DKIM signing.",
        }

    # ── Spoof / unknown ────────────────────────────────────────────────────────
    if is_tor:
        return {
            "classification": "spoof",
            "confidence": 97,
            "label": "Likely spoof",
            "reason": f"No SPF, no valid DKIM, and the sending IP resolves to a Tor exit node or known abuse ASN ({asn}). This is a strong signal of spoofing.",
            "action": "No action — advancing to p=reject will block this automatically.",
        }
    if dkim_result in ("none", "fail") and spf_result in ("none", "fail"):
        return {
            "classification": "spoof",
            "confidence": 78,
            "label": "Likely spoof",
            "reason": "No valid DKIM signature and SPF fails. This sender has no legitimate authorization to use your domain.",
            "action": "Confirm whether this is an internal tool you forgot to authenticate. If not, p=reject will block it.",
        }

    return {
        "classification": "unknown",
        "confidence": 50,
        "label": "Review needed",
        "reason": "Could not confidently classify this sender from the available authentication signals.",
        "action": "Investigate the sending IP and domain to determine if it is authorized.",
    }
