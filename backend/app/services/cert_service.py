"""
SSL certificate probing and expiry monitoring.
Probes MX hosts (port 25/STARTTLS) and mta-sts hosts (port 443).
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone

from app.services.dns_resolver import resolver as _resolver
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import Domain, SslCert, Alert

log = logging.getLogger(__name__)

# Known mail security gateways that commonly reject or silently ignore
# unsolicited probe connections from unrecognized source IPs as a
# deliberate anti-abuse measure — confirmed in practice (see conversation:
# a direct socket connect to a Mimecast inbound MX timed out on BOTH port
# 25 and port 443, ruling out a code bug). A timeout/refusal against one of
# these is informative context, not necessarily evidence the domain's own
# mail server is broken — surfaced in probe_error so it doesn't read like
# an unexplained failure.
_KNOWN_GATEWAYS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"mimecast", re.I), "Mimecast"),
    (re.compile(r"pphosted|proofpoint", re.I), "Proofpoint"),
    (re.compile(r"barracudanetworks|barracuda", re.I), "Barracuda"),
    (re.compile(r"iphmx|ironport", re.I), "Cisco IronPort"),
    (re.compile(r"fortimail", re.I), "FortiMail"),
    (re.compile(r"messagelabs|symantec", re.I), "Symantec/Broadcom Email Security"),
    (re.compile(r"trendmicro", re.I), "Trend Micro"),
    (re.compile(r"sophos", re.I), "Sophos"),
    (re.compile(r"forcepoint", re.I), "Forcepoint"),
    (re.compile(r"zixcorp|zix\b", re.I), "Zix"),
]


def _detect_gateway(host: str) -> str | None:
    for pattern, name in _KNOWN_GATEWAYS:
        if pattern.search(host):
            return name
    return None


def _annotate_error(host: str, error_kind: str | None, error_msg: str) -> str:
    """
    Turn a bare exception string into something a user can act on. A raw
    "timed out" tells you nothing about whether YOUR setup is broken or
    the other end simply won't talk to an unrecognized prober — which is
    common, deliberate behavior for major mail security gateways, not a
    misconfiguration. Only annotates timeout/refused (connectivity-level)
    failures — a DNS or TLS-chain failure isn't something a gateway vendor
    explains away.
    """
    if error_kind not in ("timeout", "refused"):
        return error_msg
    gateway = _detect_gateway(host)
    if not gateway:
        return error_msg
    verb = "timed out" if error_kind == "timeout" else "refused the connection"
    return (
        f"{error_msg} — {host} is {gateway} mail security gateway infrastructure. "
        f"These commonly {verb} for unsolicited probe connections from unrecognized "
        f"source IPs as a deliberate anti-abuse measure — this doesn't necessarily mean "
        f"there's a problem with your own mail server."
    )

EXPIRY_WARN_DAYS = 30
EXPIRY_CRIT_DAYS = 7


def _cert_status(days: int | None) -> str:
    if days is None:
        return "error"
    if days < 0:
        return "expired"
    if days <= EXPIRY_CRIT_DAYS:
        return "critical"
    if days <= EXPIRY_WARN_DAYS:
        return "expiring_soon"
    return "ok"


def _days_remaining(not_after: datetime) -> int:
    return (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def _classify_probe_exception(exc: Exception) -> str:
    """
    What kind of failure this was, not just that it failed — the difference
    between "no DNS for this host at all", "a host exists but nothing
    answers on this port" (e.g. an MX-only IP with no web server — the
    Mimecast-relay-but-no-HTTPS case), and "something answered TLS but the
    cert chain itself isn't trusted" matters for telling the user what to
    actually do next, not just that something's wrong.
    """
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, TimeoutError):  # covers asyncio.TimeoutError (alias since 3.11)
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    return "other"


async def probe_tls(host: str, port: int, starttls: bool = False) -> dict:
    """Returns cert info dict or error (with error_kind — see _classify_probe_exception)."""
    try:
        if starttls:
            # SMTP STARTTLS — grab the cert without strict hostname/chain validation.
            # Hostname validity is computed separately in _parse_cert so we can
            # still report it even when the cert doesn't match (e.g. *.mimecast.com
            # presented for za-smtp-inbound-1.mimecast.co.za).
            smtp_ctx = ssl.create_default_context()  # trusted CA bundle for chain validation
            smtp_ctx.check_hostname = False            # don't reject on hostname mismatch
            smtp_ctx.verify_mode = ssl.CERT_REQUIRED  # but DO verify the chain is trusted
            loop = asyncio.get_running_loop()
            # asyncio.wait_for here, not just the socket's own timeout=10 —
            # socket.create_connection()'s internal getaddrinfo() (DNS
            # resolution) runs before the timeout parameter takes effect, so
            # a slow/hanging resolver can blow past 10s with nothing
            # stopping it (observed in practice: ~50s for one MX host on a
            # network with slow DNS). This is the actual hard ceiling.
            cert_info = await asyncio.wait_for(
                loop.run_in_executor(None, _smtp_starttls_probe, host, port, smtp_ctx), timeout=12
            )
        else:
            # HTTPS (mta-sts on port 443) — deliberately the SAME relaxed
            # check_hostname=False pattern as STARTTLS above, not strict
            # validation. Strict check_hostname=True aborts the TLS
            # handshake itself the instant the cert doesn't match — which
            # means we'd never see WHAT cert was actually presented (e.g.
            # mta-sts.customerdomain.com pointed at shared gateway
            # infrastructure presenting *.mimecast.com). Relaxing this lets
            # the handshake complete, the real cert get captured, and
            # hostname_valid get computed honestly in _parse_cert — turning
            # an opaque "https error" into "HTTPS works, but the cert
            # covers X, not your domain." Still server_hostname=host for
            # SNI, so a host capable of per-tenant routing gets the chance
            # to present the right cert. verify_mode stays CERT_REQUIRED so
            # a genuinely self-signed/untrusted cert still fails distinctly
            # (error_kind="tls"), not silently passed as valid.
            https_ctx = ssl.create_default_context()
            https_ctx.check_hostname = False
            https_ctx.verify_mode = ssl.CERT_REQUIRED
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=https_ctx, server_hostname=host), timeout=10
            )
            cert = writer.get_extra_info("ssl_object").getpeercert()
            writer.close()
            await writer.wait_closed()
            cert_info = _parse_cert(cert, host)

        return cert_info
    except Exception as e:
        return {"error": str(e), "error_kind": _classify_probe_exception(e)}


def _smtp_starttls_probe(host: str, port: int, ctx: ssl.SSLContext) -> dict:
    """Synchronous SMTP STARTTLS probe (run in executor)."""
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.recv(1024)  # banner
        sock.sendall(f"EHLO sentinel.check\r\n".encode())
        ehlo_resp = sock.recv(4096).decode(errors="replace")
        if "STARTTLS" not in ehlo_resp:
            return {"error": "STARTTLS not supported", "starttls_supported": False}
        sock.sendall(b"STARTTLS\r\n")
        sock.recv(1024)
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        cert = tls_sock.getpeercert()
        tls_version = tls_sock.version()
        tls_sock.close()
        result = _parse_cert(cert, host)
        result["tls_version"] = tls_version
        result["starttls_supported"] = True
        return result


def _parse_cert(cert: dict, host: str) -> dict:
    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")
    try:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        not_after = not_before = None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    days = _days_remaining(not_after) if not_after else None

    return {
        "subject_cn": subject.get("commonName"),
        "issuer": issuer.get("organizationName"),
        "san": ",".join(san_list),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days,
        "hostname_valid": host in san_list or any(
            s.startswith("*.") and host.endswith(s[1:]) for s in san_list
        ),
        "error": None,
    }


async def probe_domain_certs(db: AsyncSession, domain: Domain) -> list[SslCert]:
    """Probe all relevant hosts for a domain and upsert SslCert rows."""
    hosts_to_probe: list[tuple[str, str, int, bool]] = []

    # MX hosts
    try:
        mx_answers = await _resolver.resolve(domain.name, "MX")
        for mx in mx_answers:
            host = str(mx.exchange).rstrip(".")
            hosts_to_probe.append((host, "mx", 25, True))
    except Exception:
        pass

    # mta-sts host
    hosts_to_probe.append((f"mta-sts.{domain.name}", "mta-sts", 443, False))

    # Probe every host concurrently, not sequentially — each probe is
    # individually bounded (~12s worst case), but probing 2-3 hosts one at
    # a time could otherwise take 30-60+s for a single domain, long enough
    # for a browser, dev proxy, or any intermediary to drop the connection
    # mid-request (the actual cause of "probe finished but no results" with
    # a misleading network/CORS error in the console). Concurrent probing
    # bounds total wall time to the slowest single host instead of the sum.
    results = await asyncio.gather(
        *(probe_tls(host, port, starttls=starttls) for host, host_type, port, starttls in hosts_to_probe)
    )

    certs = []
    for (host, host_type, port, starttls), result in zip(hosts_to_probe, results):
        # Upsert
        existing = await db.execute(
            select(SslCert).where(SslCert.domain_id == domain.id, SslCert.host == host)
        )
        cert_row = existing.scalar_one_or_none()
        if not cert_row:
            cert_row = SslCert(id=uuid.uuid4(), domain_id=domain.id, host=host, host_type=host_type, port=port)
            db.add(cert_row)

        if "error" in result and result["error"]:
            error_kind = result.get("error_kind")
            cert_row.probe_error = _annotate_error(host, error_kind, result["error"])
            cert_row.error_kind = error_kind
            cert_row.status = "error"
            cert_row.starttls_supported = result.get("starttls_supported")
        else:
            cert_row.subject_cn = result.get("subject_cn")
            cert_row.issuer = result.get("issuer")
            cert_row.san = result.get("san")
            cert_row.not_before = result.get("not_before")
            cert_row.not_after = result.get("not_after")
            cert_row.days_remaining = result.get("days_remaining")
            cert_row.tls_version = result.get("tls_version")
            cert_row.starttls_supported = result.get("starttls_supported", True)
            cert_row.hostname_valid = result.get("hostname_valid")
            cert_row.probe_error = None
            cert_row.error_kind = None
            cert_row.status = _cert_status(cert_row.days_remaining)

        cert_row.probed_at = datetime.now(timezone.utc)
        certs.append(cert_row)

    await db.commit()

    # Fire alerts for expiring / expired certs
    for cert in certs:
        if cert.status in ("critical", "expired", "expiring_soon"):
            await _maybe_create_cert_alert(db, domain, cert)

    return certs


async def _maybe_create_cert_alert(db: AsyncSession, domain: Domain, cert: SslCert) -> None:
    from app.models import Alert
    severity = "critical" if cert.status in ("critical", "expired") else "warn"
    title = f"{cert.host} certificate {'expired' if cert.status == 'expired' else f'expires in {cert.days_remaining} days'}"
    existing = await db.execute(
        select(Alert).where(
            Alert.domain_id == domain.id,
            Alert.category == "cert",
            Alert.title == title,
        )
    )
    if existing.scalar_one_or_none():
        return
    alert = Alert(
        id=uuid.uuid4(),
        domain_id=domain.id,
        tenant_id=domain.tenant_id,
        severity=severity,
        category="cert",
        title=title,
        body=f"The certificate on {cert.host} (type: {cert.host_type}) {'has expired' if cert.status == 'expired' else f'expires in {cert.days_remaining} days'}.",
        action=(
            "Renew this certificate immediately — expired certs actively block delivery."
            if cert.status in ("critical", "expired")
            else "Renew before enabling MTA-STS enforce, or active sessions may be rejected once it lapses."
        ),
    )
    db.add(alert)
    await db.commit()


async def probe_all_domains() -> None:
    """Background job: probe every active domain."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Domain).where(Domain.is_active == True))
        domains = result.scalars().all()
        for domain in domains:
            try:
                await probe_domain_certs(db, domain)
            except Exception:
                log.exception("Cert probe failed for %s", domain.name)
