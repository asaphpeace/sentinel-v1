"""
DNS publishing hand-holding — Phase 1 of GUIDED_ONBOARDING_PLAN.md Part 1.

Auto-detects a domain's registrar/DNS provider from its NS records (data
already fetched via dns_resolver.py, just pattern-matched against known
nameserver suffixes) and returns curated, provider-specific publishing
instructions — prioritising the registrars this market's actual customers
use (cPanel/WHM shared hosting, Afrihost, Xneelo, Domains.co.za) rather than
just the international giants that already have good generic documentation.

No write access to any provider here — this is the permanent universal
fallback described in the plan; Domain Connect/Entri (Phase 2) is separate,
later work for the providers that support it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.services.dns_resolver import resolver
import dns.exception


@dataclass
class RegistrarInstructions:
    key: str
    name: str
    steps: list[str] = field(default_factory=list)
    help_url: str | None = None

    def steps_for(self, record_type: str) -> list[str]:
        """
        steps is written with a `{type}` placeholder instead of a hardcoded
        "TXT" so the exact same provider instructions can be reused for a
        DKIM publish step too — DKIM is a CNAME for most platforms
        (SendGrid, Mailchimp, M365, HubSpot, Amazon SES, Mimecast...), and
        reusing TXT-flavoured wording there would be actively wrong, not
        just imprecise.
        """
        return [s.format(type=record_type) for s in self.steps]


# Ordered by how common each is among this product's actual target market —
# SA shared hosting / SMB registrars first, then the international giants
# Domain Connect already documents well elsewhere.
_REGISTRARS: list[tuple[re.Pattern, RegistrarInstructions]] = [
    (re.compile(r"afrihost", re.I), RegistrarInstructions(
        key="afrihost", name="Afrihost",
        steps=[
            "Log in to your Afrihost Client Zone at clientzone.afrihost.com",
            "Go to My Services → Domains, select this domain, then \"Manage DNS\"",
            "Click \"Add Record\", set Type to {type}",
            "Enter the Host/Name and Value exactly as shown below",
            "Save — Afrihost DNS changes are usually live within 1-2 hours",
        ],
        help_url="https://clientzone.afrihost.com",
    )),
    (re.compile(r"xneelo|hetzner", re.I), RegistrarInstructions(
        key="xneelo", name="Xneelo",
        steps=[
            "Log in to your Xneelo control panel (My Sites)",
            "Select the domain, then open \"DNS Settings\"",
            "Click \"Add Record\", choose {type} as the record type",
            "Enter the Host/Name and Value exactly as shown below",
            "Save — Xneelo changes typically propagate within an hour",
        ],
        help_url="https://www.xneelo.co.za/",
    )),
    (re.compile(r"domains\.co\.za|registrar\.co\.za", re.I), RegistrarInstructions(
        key="domains_co_za", name="Domains.co.za",
        steps=[
            "Log in to your Domains.co.za client area",
            "Select this domain, then go to \"DNS Management\"",
            "Add a new {type} record with the Host/Name and Value shown below",
            "Save changes",
        ],
        help_url="https://www.domains.co.za/",
    )),
    (re.compile(r"cpanel|whm|directadmin", re.I), RegistrarInstructions(
        key="cpanel", name="cPanel / WHM (shared hosting)",
        steps=[
            "Log in to your hosting cPanel (usually at yourdomain.co.za/cpanel or a port-2083 URL your host gave you)",
            "Open the \"Zone Editor\" tool under the Domains section",
            "Select this domain, click \"+ {type} Record\"",
            "Enter the Host/Name and Value exactly as shown below",
            "Save — if you don't manage hosting yourself, use \"Email these instructions\" below to send this to whoever does",
        ],
        help_url=None,
    )),
    (re.compile(r"cloudflare", re.I), RegistrarInstructions(
        key="cloudflare", name="Cloudflare",
        steps=[
            "Log in to dash.cloudflare.com and select this domain",
            "Go to the DNS tab",
            "Click \"Add record\", set Type to {type}",
            "Enter the Name and Content exactly as shown below, leave Proxy status off (DNS only)",
            "Save — Cloudflare changes are usually live within minutes",
        ],
        help_url="https://dash.cloudflare.com/",
    )),
    (re.compile(r"godaddy", re.I), RegistrarInstructions(
        key="godaddy", name="GoDaddy",
        steps=[
            "Log in to your GoDaddy account and go to \"My Products\" → DNS for this domain",
            "Click \"Add\" under Records, select {type}",
            "Enter the Host and Value exactly as shown below",
            "Save — GoDaddy changes can take up to an hour",
        ],
        help_url="https://dcc.godaddy.com/",
    )),
    (re.compile(r"google domains|googledomains|squarespace", re.I), RegistrarInstructions(
        key="google_domains", name="Google Domains / Squarespace Domains",
        steps=[
            "Open your domain's DNS settings",
            "Add a custom resource record, type {type}",
            "Enter the Host and Data exactly as shown below",
            "Save",
        ],
        help_url=None,
    )),
    (re.compile(r"google\.com|googlehosting|ghs\.googlehosting", re.I), RegistrarInstructions(
        key="google_workspace", name="Google Workspace (domain hosted via Google)",
        steps=[
            "Open the Google Admin console at admin.google.com",
            "Go to Domains → Manage Domains, select this domain's DNS settings",
            "Add a custom record, type {type}",
            "Enter the Host and Value exactly as shown below",
            "Save",
        ],
        help_url="https://admin.google.com/",
    )),
    (re.compile(r"namecheap", re.I), RegistrarInstructions(
        key="namecheap", name="Namecheap",
        steps=[
            "Log in to Namecheap and go to Domain List → Manage for this domain",
            "Open the \"Advanced DNS\" tab",
            "Click \"Add New Record\", select {type} Record",
            "Enter the Host and Value exactly as shown below",
            "Save",
        ],
        help_url="https://ap.www.namecheap.com/",
    )),
]

_GENERIC_FALLBACK = RegistrarInstructions(
    key="generic", name="Your DNS provider",
    steps=[
        "We couldn't automatically recognise your DNS provider from its nameservers",
        "Log in to wherever you manage DNS for this domain (often your registrar or hosting control panel)",
        "Find the section for adding a {type} record (sometimes called \"DNS records\", \"Zone editor\", or \"Advanced DNS\")",
        "Enter the Host/Name and Value exactly as shown below",
        "Save — if you're not sure who manages DNS for this domain, use \"Email these instructions\" below to send this to whoever does",
    ],
    help_url=None,
)


def _match_registrar(nameservers: list[str]) -> RegistrarInstructions:
    """Pure matching logic, split out from the DNS lookup so it's testable without a resolver."""
    joined = " ".join(nameservers)
    for pattern, instructions in _REGISTRARS:
        if pattern.search(joined):
            return instructions
    return _GENERIC_FALLBACK


async def detect_registrar(domain_name: str) -> tuple[RegistrarInstructions, list[str]]:
    """
    Returns (instructions, nameservers). Falls back to generic instructions
    (never an error) when nameservers can't be resolved or don't match any
    curated pattern — DNS lookups fail for plenty of legitimate reasons
    (newly registered domain, resolver hiccup) and that's not a reason to
    block the hand-holding flow.
    """
    try:
        answers = await resolver.resolve(domain_name, "NS")
        nameservers = sorted(str(r.target).rstrip(".").lower() for r in answers)
    except dns.exception.DNSException:
        return _GENERIC_FALLBACK, []

    return _match_registrar(nameservers), nameservers
