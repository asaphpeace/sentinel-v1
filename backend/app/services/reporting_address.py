"""
Generate and resolve unique reporting email addresses.
Each domain gets a short hex slug: <slug>@mailsentry.co.za
The slug is derived from uuid4 so it's globally unique and not guessable.
"""
import secrets
from app.config import settings


def generate_slug() -> str:
    """8-char hex slug, e.g. 'd4a9f2b1'."""
    return secrets.token_hex(4)


def reporting_address(slug: str) -> str:
    """Full RUA/RUF address for a domain slug."""
    return f"{slug}@{settings.reporting_domain}"


def rua_mailto(slug: str) -> str:
    return f"mailto:{reporting_address(slug)}"
