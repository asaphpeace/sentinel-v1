"""
Sending Platform Library — PAIN_POINT_RESOLUTION_PLAN.md Pain 1.

Structured setup data per sending platform: the exact SPF mechanism, the
exact DKIM setup type, where in that platform's own admin UI it's
configured, and known gotchas. This is what turns a generic "add an SPF
include" into "add this exact value, here's where to find it in
SendGrid" — the actual answer that used to require a meeting.

Distinct from app/knowledge/dmarc.py etc: those are general protocol facts
for the AI advisor to cite. This is structured product data consumed by
the platform setup UI (PlatformSetupModal) and by compose_spf_record() —
no LLM involved, pure data, fully unit-testable.

Mimecast is NOT modeled like the others. Every other v1 platform signs
and sends mail directly. Mimecast is most commonly deployed as an
outbound relay/gateway in front of a customer's own mail server — the
origin server may still do its own DKIM signing while Mimecast just
relays the message onward, or Mimecast may be configured to re-sign.
Giving it the same "we sign your mail" template as SendGrid would be
wrong for the most common real deployment, so it carries an explicit
deployment-mode branch instead of a single profile.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SpfMechanism:
    mechanism: str          # e.g. "include:sendgrid.net"
    lookup_cost: int = 1    # DNS lookups this mechanism consumes — see dmarc.spf_lookup_limit


@dataclass(frozen=True)
class DkimSetup:
    kind: str                          # "cname" | "txt"
    description: str
    selector_pattern: str | None = None


@dataclass(frozen=True)
class PlatformProfile:
    key: str
    name: str
    category: str                      # esp | relay_gateway | groupware
    spf: tuple[SpfMechanism, ...] = ()
    dkim: DkimSetup | None = None
    admin_path: tuple[str, ...] = ()
    gotchas: tuple[str, ...] = ()
    return_path_note: str | None = None   # custom/branded return-path mechanism, if any


# ── Mimecast — deployment-mode branch, not a single profile ─────────────────

MIMECAST_DIRECT = PlatformProfile(
    key="mimecast_direct",
    name="Mimecast (sending directly through Mimecast)",
    category="esp",
    spf=(SpfMechanism("include:_netblocks.mimecast.com", 1),),
    dkim=DkimSetup(
        kind="cname",
        description="Mimecast issues a DKIM CNAME pair per domain via Domain Authentication in Administration Console.",
        selector_pattern="mimecast20XXXX (date-coded selector, varies by setup date)",
    ),
    admin_path=(
        "Log in to Mimecast Administration Console",
        "Go to Administration → Gateway → Domains",
        "Select this domain, open the DKIM tab",
        "Generate or view the existing DKIM key — Mimecast provides the exact CNAME records to publish",
    ),
    gotchas=(
        "Mimecast's SPF netblock list is occasionally region-specific — confirm with their current "
        "documentation if mail still fails after publishing the standard include.",
    ),
)

MIMECAST_RELAY = PlatformProfile(
    key="mimecast_relay",
    name="Mimecast (relaying for your own mail server)",
    category="relay_gateway",
    spf=(SpfMechanism("include:_netblocks.mimecast.com", 1),),
    dkim=None,  # deliberately — DKIM signing in this mode usually still happens at the origin server
    admin_path=(
        "Mimecast in this mode is a gateway in front of your existing mail server (Exchange, "
        "Postfix, etc.) — it relays outbound mail through Mimecast's infrastructure without "
        "necessarily re-signing it.",
        "Check your own mail server's DKIM configuration first — if it already signs outbound "
        "mail, that signature should survive the relay unless Mimecast's outbound routing rules "
        "are configured to strip or rewrite headers.",
        "Mimecast's SPF include only covers the IPs Mimecast relays from — your origin server's "
        "own sending IP, if it ever sends directly (not through Mimecast), needs its own SPF entry too.",
    ),
    gotchas=(
        "The single most common cause of unexpected DMARC failures in this deployment mode: "
        "someone assumes Mimecast \"handles DKIM\" the way a direct-send ESP does, when in relay "
        "mode the signing responsibility usually still sits with the origin server.",
    ),
)


# ── v1 platform set — confirmed present in source_classifier.py/verdict_service.py ──

SENDGRID = PlatformProfile(
    key="sendgrid", name="SendGrid", category="esp",
    spf=(SpfMechanism("include:sendgrid.net", 1),),
    dkim=DkimSetup("cname", "SendGrid issues 3 CNAME records under Domain Authentication in Sender Authentication settings.", "s1, s2 (default)"),
    admin_path=("Log in to SendGrid", "Settings → Sender Authentication", "Authenticate Your Domain — follow the wizard for the exact CNAME values"),
    gotchas=("Until domain authentication is completed in SendGrid's own dashboard, SendGrid signs with its own domain — DKIM will show as unaligned, not broken.",),
)

MAILCHIMP = PlatformProfile(
    key="mailchimp", name="Mailchimp", category="esp",
    spf=(SpfMechanism("include:servers.mcsv.net", 1),),
    dkim=DkimSetup("cname", "Mailchimp provides a CNAME under Domain Verification in account settings.", "k1, k2, k3 (default)"),
    admin_path=("Log in to Mailchimp", "Account → Settings → Domains", "Verify a domain — follow the DNS instructions shown"),
)

MICROSOFT_365 = PlatformProfile(
    key="microsoft_365", name="Microsoft 365", category="groupware",
    spf=(SpfMechanism("include:spf.protection.outlook.com", 1),),
    dkim=DkimSetup("cname", "Two CNAMEs per selector, enabled per domain in the Microsoft 365 Defender portal.", "selector1, selector2"),
    admin_path=("Microsoft 365 Defender portal", "Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM", "Select the domain, enable DKIM signing — it provides the exact CNAME pair"),
    gotchas=(
        "Hybrid setups (some mail flows through an on-prem server, not just M365) need that server's own IPs added to SPF too — the M365 include alone only covers mail sent from Microsoft's infrastructure.",
    ),
)

GOOGLE_WORKSPACE = PlatformProfile(
    key="google_workspace", name="Google Workspace", category="groupware",
    spf=(SpfMechanism("include:_spf.google.com", 1),),
    dkim=DkimSetup("txt", "A single TXT key generated in the Admin console, published at a Google-chosen selector.", "google"),
    admin_path=("admin.google.com", "Apps → Google Workspace → Gmail → Authenticate email", "Generate new record — copy the exact selector and TXT value shown"),
)

HUBSPOT = PlatformProfile(
    key="hubspot", name="HubSpot", category="esp",
    spf=(SpfMechanism("include:hubspotemail.net", 1),),
    dkim=DkimSetup("cname", "HubSpot issues 3 CNAMEs under domain connection settings.", "hs1-_domainkey, hs2-_domainkey"),
    admin_path=("HubSpot Settings", "Website → Domains & URLs", "Connect a domain for sending — follow the CNAME instructions shown"),
)

SALESFORCE_MC = PlatformProfile(
    key="salesforce_mc", name="Salesforce Marketing Cloud", category="esp",
    spf=(SpfMechanism("include:mc.exacttarget.com", 1),),
    dkim=DkimSetup("cname", "CNAMEs issued per sending domain under Sender Authentication Package (SAP) setup.", "varies — provided per SAP setup"),
    admin_path=("Marketing Cloud Setup", "Sender Authentication Package", "Follow the domain authentication wizard for exact DNS values"),
    return_path_note="Marketing Cloud's bounce domain (envelope-from) differs from your sending domain by design — this is the SAP/branded return-path setup, configure it here to align SPF.",
)

KLAVIYO = PlatformProfile(
    key="klaviyo", name="Klaviyo", category="esp",
    spf=(SpfMechanism("include:_spf.klaviyo.com", 1),),
    dkim=DkimSetup("cname", "Two CNAMEs shown under Settings → Domains → Authentication.", "varies per account"),
    admin_path=("Klaviyo Settings", "Domains → Authentication", "Follow the DNS setup steps shown"),
)

ZENDESK = PlatformProfile(
    key="zendesk", name="Zendesk", category="esp",
    spf=(SpfMechanism("include:mail.zendesk.com", 1),),
    dkim=DkimSetup("txt", "A TXT key under Admin Center → Channels → Talk and email → Email.", "zendesk1"),
    admin_path=("Zendesk Admin Center", "Channels → Talk and email → Email", "Add a custom domain — follow the DKIM/SPF instructions shown"),
)

POSTMARK = PlatformProfile(
    key="postmark", name="Postmark", category="esp",
    spf=(SpfMechanism("include:spf.mtasv.net", 1),),
    dkim=DkimSetup("txt", "A single TXT key shown under Sender Signatures → DKIM.", "pm (default)"),
    admin_path=("Postmark account", "Sender Signatures → your domain → DKIM", "Copy the exact TXT value shown"),
)

SPARKPOST = PlatformProfile(
    key="sparkpost", name="SparkPost", category="esp",
    spf=(SpfMechanism("include:sparkpostmail.com", 1),),
    dkim=DkimSetup("txt", "A TXT key under Account → Sending Domains.", "scph (default)"),
    admin_path=("SparkPost dashboard", "Account → Sending Domains", "Add/verify a domain — copy the DKIM TXT value shown"),
)

AMAZON_SES = PlatformProfile(
    key="amazon_ses", name="Amazon SES", category="esp",
    spf=(SpfMechanism("include:amazonses.com", 1),),
    dkim=DkimSetup("cname", "Three CNAMEs (Easy DKIM) generated per identity in the SES console.", "auto-generated per identity"),
    admin_path=("AWS SES console", "Verified identities → your domain → DKIM", "Enable Easy DKIM — copy the 3 CNAME records shown"),
)

MAILGUN = PlatformProfile(
    key="mailgun", name="Mailgun", category="esp",
    spf=(SpfMechanism("include:mailgun.org", 1),),
    dkim=DkimSetup("txt", "A TXT key shown under Sending → Domains → DNS records.", "smtp._domainkey (default)"),
    admin_path=("Mailgun control panel", "Sending → Domains → your domain", "DNS records tab — copy the exact TXT value shown"),
)

CONSTANT_CONTACT = PlatformProfile(
    key="constant_contact", name="Constant Contact", category="esp",
    spf=(SpfMechanism("include:constantcontact.com", 1),),
    dkim=DkimSetup("cname", "CNAME shown under My Settings → Domain Authentication.", "ccdkim (default)"),
    admin_path=("Constant Contact account", "My Settings → Domain Authentication", "Follow the DNS setup steps shown"),
)

ACTIVECAMPAIGN = PlatformProfile(
    key="activecampaign", name="ActiveCampaign", category="esp",
    spf=(SpfMechanism("include:mail.activehosted.com", 1),),
    dkim=DkimSetup("cname", "CNAME shown under Settings → Sending Domain Authentication.", "varies per account"),
    admin_path=("ActiveCampaign Settings", "Sending Domain Authentication", "Follow the DNS setup steps shown"),
)

PARDOT = PlatformProfile(
    key="pardot", name="Pardot (Salesforce)", category="esp",
    spf=(SpfMechanism("include:pardot.com", 1),),
    dkim=DkimSetup("txt", "DKIM key generated per sending domain under Domain Management.", "varies per account"),
    admin_path=("Pardot Settings", "Domain Management", "Follow the domain authentication wizard for exact values"),
)

MARKETO = PlatformProfile(
    key="marketo", name="Marketo", category="esp",
    spf=(SpfMechanism("include:mktomail.com", 1),),
    dkim=DkimSetup("cname", "CNAME shown under Admin → Email → DKIM Settings.", "varies per account"),
    admin_path=("Marketo Admin", "Email → DKIM Settings", "Follow the DNS setup steps shown"),
)

ZOHO = PlatformProfile(
    key="zoho", name="Zoho", category="groupware",
    spf=(SpfMechanism("include:zoho.com", 1),),
    dkim=DkimSetup("txt", "TXT key shown under Zoho Mail Admin Console → Domains → DKIM.", "zoho (default)"),
    admin_path=("Zoho Mail Admin Console", "Domains → your domain → DKIM", "Copy the exact TXT value shown"),
)


PLATFORM_PROFILES: dict[str, PlatformProfile] = {
    p.key: p for p in [
        SENDGRID, MAILCHIMP, MICROSOFT_365, GOOGLE_WORKSPACE, HUBSPOT,
        SALESFORCE_MC, KLAVIYO, ZENDESK, POSTMARK, SPARKPOST, AMAZON_SES,
        MAILGUN, CONSTANT_CONTACT, ACTIVECAMPAIGN, PARDOT, MARKETO, ZOHO,
    ]
}

# Mimecast isn't in PLATFORM_PROFILES directly — it requires a deployment-mode
# choice before a profile can be selected at all (see module docstring).
MIMECAST_BRANCHES: dict[str, PlatformProfile] = {
    "direct": MIMECAST_DIRECT,
    "relay": MIMECAST_RELAY,
}

# Platforms confirmed present in the existing classifiers (source_classifier.py's
# KNOWN_ESPS / verdict_service.py's _KNOWN_ESPS) — used to map a detected
# source straight to a profile without guessing key-name spelling.
_DETECTED_NAME_TO_KEY: dict[str, str] = {
    "google workspace": "google_workspace", "microsoft 365": "microsoft_365",
    "mailchimp": "mailchimp", "sendgrid": "sendgrid", "amazon ses": "amazon_ses",
    "mailgun": "mailgun", "postmark": "postmark", "sparkpost": "sparkpost",
    "hubspot": "hubspot", "salesforce": "salesforce_mc", "salesforce mc": "salesforce_mc",
    "zoho": "zoho", "constant contact": "constant_contact", "klaviyo": "klaviyo",
    "zendesk": "zendesk", "marketo": "marketo", "campaign monitor": None,  # no profile yet
}


def get_platform(key: str) -> PlatformProfile | None:
    return PLATFORM_PROFILES.get(key)


def platform_key_for_detected_name(detected_name: str) -> str | None:
    """Map a name already produced by source_classifier.py/verdict_service.py
    (e.g. "SendGrid", "Google Workspace") to a platform library key, if one exists."""
    return _DETECTED_NAME_TO_KEY.get(detected_name.strip().lower())


def all_platform_keys(include_mimecast_branches: bool = True) -> list[str]:
    keys = list(PLATFORM_PROFILES.keys())
    if include_mimecast_branches:
        keys = ["mimecast_direct", "mimecast_relay"] + keys
    return keys
