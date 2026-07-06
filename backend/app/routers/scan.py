"""
Public domain scan — no auth required.
Live DNS + TLS probe of any domain with a posture verdict.
"""
# Deliberately no `from __future__ import annotations` here — slowapi's
# @limiter.limit decorator wraps this module's route functions, and that
# wrapper's __globals__ don't include this module's names, which breaks
# pydantic's forward-ref resolution for string-form annotations. Nothing in
# this file needs postponed evaluation (Python 3.9+ already supports
# list[Finding] natively), so the simplest fix is to not use it.

import asyncio
import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.resolver as _sync_resolver

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.rate_limit import limiter
from app.services.dns_resolver import resolver as _resolver

router = APIRouter(prefix="/scan", tags=["scan"])


class ScanRequest(BaseModel):
    domain: str


class Finding(BaseModel):
    category: str   # spf | dmarc | mx | mta_sts | cert | bimi
    status: str     # pass | warn | fail | info
    title: str
    detail: str


class ScanResult(BaseModel):
    domain: str
    score: int
    grade: str
    grade_color: str
    summary: str
    findings: list[Finding]
    raw: dict
    is_email_domain: bool = True


def _grade(score: int) -> tuple[str, str]:
    if score >= 90: return "A", "#34e0a1"
    if score >= 80: return "B", "#2ee6c5"
    if score >= 70: return "C", "#f5c542"
    if score >= 50: return "D", "#f5a23d"
    return "F", "#ff4d6d"


async def _domain_exists(domain: str) -> bool:
    """
    Returns False only on a definitive NXDOMAIN for the apex domain.
    Any other failure (timeout, SERVFAIL, no A record) returns True
    so we don't false-positive on infrastructure issues.
    """
    for qtype in ("A", "NS"):
        try:
            await _resolver.resolve(domain, qtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            continue  # timeout / SERVFAIL / no record of this type — try next
    return True  # assume exists if all queries failed for reasons other than NXDOMAIN


async def _resolve_txt(name: str) -> list[str]:
    try:
        answers = await _resolver.resolve(name, "TXT")
        return [
            "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
            for r in answers
        ]
    except Exception:
        return []


async def _resolve_mx(domain: str) -> list[tuple[int, str]]:
    try:
        answers = await _resolver.resolve(domain, "MX")
        return sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
    except Exception:
        return []


async def _fetch_mta_sts_policy(domain: str) -> str | None:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            r = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
            if r.status_code == 200:
                return r.text
    except Exception:
        pass
    return None


def _probe_cert_sync(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after_str = cert.get("notAfter", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        return {"days": days, "not_after": not_after_str}
    except ssl.SSLCertVerificationError as e:
        return {"error": f"certificate verification failed: {e}"}
    except Exception as e:
        return {"error": str(e)}


@router.post("", response_model=ScanResult)
@limiter.limit("10/minute")
async def scan_domain(request: Request, req: ScanRequest):
    domain = req.domain.lower().strip().rstrip(".")

    if not await _domain_exists(domain):
        raise HTTPException(status_code=404, detail="domain_not_found")

    # All lookups + probes in one parallel gather
    loop = asyncio.get_running_loop()
    results = await asyncio.gather(
        _resolve_txt(domain),
        _resolve_txt(f"_dmarc.{domain}"),
        _resolve_mx(domain),
        _resolve_txt(f"_mta-sts.{domain}"),
        _resolve_txt(f"default._bimi.{domain}"),
        _fetch_mta_sts_policy(domain),
        loop.run_in_executor(None, _probe_cert_sync, f"mta-sts.{domain}"),
        return_exceptions=True,
    )
    def _safe(r, default):
        return default if isinstance(r, BaseException) else r

    spf_txts     = _safe(results[0], [])
    dmarc_txts   = _safe(results[1], [])
    mx_hosts     = _safe(results[2], [])
    mta_sts_txts = _safe(results[3], [])
    bimi_txts    = _safe(results[4], [])
    mta_sts_policy = _safe(results[5], None)
    cert_info      = _safe(results[6], {"error": "probe failed"})

    findings: list[Finding] = []
    score = 0

    # ── SPF (max 20 pts) ─────────────────────────────────────────────────────
    spf_record = next((t for t in spf_txts if t.startswith("v=spf1")), None)
    if not spf_record:
        findings.append(Finding(
            category="spf", status="fail",
            title="No SPF record",
            detail="Anyone can send email claiming to be from this domain with no authentication check.",
        ))
    elif "+all" in spf_record:
        score += 5
        findings.append(Finding(
            category="spf", status="fail",
            title="SPF allows any sender (+all)",
            detail=f"{spf_record}\n\n+all grants a pass to every IP address — SPF provides no protection.",
        ))
    elif "~all" in spf_record:
        score += 15
        findings.append(Finding(
            category="spf", status="warn",
            title="SPF softfail (~all)",
            detail=f"{spf_record}\n\n~all marks unauthorised senders as suspicious but does not reject them. Consider -all.",
        ))
    else:
        score += 20
        findings.append(Finding(
            category="spf", status="pass",
            title="SPF configured",
            detail=spf_record,
        ))

    # ── DMARC (max 40 pts) ───────────────────────────────────────────────────
    dmarc_record = next((t for t in dmarc_txts if t.startswith("v=DMARC1")), None)
    if not dmarc_record:
        findings.append(Finding(
            category="dmarc", status="fail",
            title="No DMARC record",
            detail="Without DMARC there is no policy telling receivers what to do with emails that fail SPF/DKIM. Phishing using this domain is unconstrained.",
        ))
    else:
        policy = ""
        pct = 100
        for part in dmarc_record.split(";"):
            p = part.strip().lower()
            if p.startswith("p="):
                policy = p.split("=", 1)[1].strip()
            elif p.startswith("pct="):
                try: pct = int(p.split("=", 1)[1].strip())
                except: pass

        if policy == "reject":
            pts = 40 if pct >= 100 else 30
            score += pts
            partial = f" for {pct}% of messages" if pct < 100 else ""
            findings.append(Finding(
                category="dmarc", status="pass" if pct >= 100 else "warn",
                title=f"DMARC p=reject{' (partial)' if pct < 100 else ''}",
                detail=f"{dmarc_record}\n\nAll unauthorised senders are rejected{partial}. This is the strongest protection.",
            ))
        elif policy == "quarantine":
            score += 25
            findings.append(Finding(
                category="dmarc", status="warn",
                title="DMARC p=quarantine",
                detail=f"{dmarc_record}\n\nUnauthorised senders are moved to spam. Consider advancing to p=reject.",
            ))
        elif policy == "none":
            score += 10
            findings.append(Finding(
                category="dmarc", status="warn",
                title="DMARC monitoring only (p=none)",
                detail=f"{dmarc_record}\n\nDMARC is published but no enforcement action is taken. Phishing emails are not blocked.",
            ))
        else:
            score += 5
            findings.append(Finding(
                category="dmarc", status="warn",
                title=f"DMARC present (unknown policy: {policy or 'none'})",
                detail=dmarc_record,
            ))

    # ── MX (info only) ───────────────────────────────────────────────────────
    if not mx_hosts:
        findings.append(Finding(
            category="mx", status="info",
            title="No MX records",
            detail="This domain does not appear to receive email.",
        ))
    else:
        mx_detail = "\n".join(f"  pri {pri}  {host}" for pri, host in mx_hosts)
        findings.append(Finding(
            category="mx", status="info",
            title=f"{len(mx_hosts)} MX record{'s' if len(mx_hosts) != 1 else ''}",
            detail=mx_detail,
        ))

    # ── MTA-STS (max 25 pts) ─────────────────────────────────────────────────
    mta_sts_txt = next((t for t in mta_sts_txts if "v=STSv1" in t), None)
    if not mta_sts_txt:
        findings.append(Finding(
            category="mta_sts", status="fail",
            title="No MTA-STS policy",
            detail="Senders are not required to use TLS when delivering email to this domain. Plaintext interception is possible.",
        ))
    else:
        mode = ""
        if mta_sts_policy:
            for line in mta_sts_policy.splitlines():
                if line.lower().startswith("mode:"):
                    mode = line.split(":", 1)[1].strip().lower()
                    break
        if mode == "enforce":
            score += 25
            findings.append(Finding(
                category="mta_sts", status="pass",
                title="MTA-STS enforce",
                detail="All senders must use TLS. Email that cannot be delivered over TLS will be rejected.",
            ))
        elif mode == "testing":
            score += 10
            findings.append(Finding(
                category="mta_sts", status="warn",
                title="MTA-STS testing mode",
                detail="MTA-STS is published but violations are only reported, not enforced. Advance to enforce when ready.",
            ))
        else:
            score += 5
            findings.append(Finding(
                category="mta_sts", status="warn",
                title=f"MTA-STS present (mode: {mode or 'unknown'})",
                detail=mta_sts_txt,
            ))

    # ── TLS cert (max 15 pts) ────────────────────────────────────────────────
    if isinstance(cert_info, dict) and "error" not in cert_info:
        days = cert_info.get("days", 0)
        if days < 0:
            findings.append(Finding(
                category="cert", status="fail",
                title="MTA-STS certificate expired",
                detail=f"mta-sts.{domain} — expired {abs(days)} day{'s' if abs(days) != 1 else ''} ago. Renew immediately.",
            ))
        elif days <= 7:
            score += 5
            findings.append(Finding(
                category="cert", status="fail",
                title=f"Certificate expires in {days} days",
                detail=f"mta-sts.{domain} — critical: renew before enabling MTA-STS enforce.",
            ))
        elif days <= 30:
            score += 10
            findings.append(Finding(
                category="cert", status="warn",
                title=f"Certificate expires in {days} days",
                detail=f"mta-sts.{domain} — schedule renewal soon (expires {cert_info.get('not_after', '')}).",
            ))
        else:
            score += 15
            findings.append(Finding(
                category="cert", status="pass",
                title=f"Certificate valid — {days} days remaining",
                detail=f"mta-sts.{domain} — expires {cert_info.get('not_after', '')}.",
            ))
    else:
        err = cert_info.get("error", "probe failed") if isinstance(cert_info, dict) else "probe failed"
        findings.append(Finding(
            category="cert", status="info",
            title="Certificate not available",
            detail=f"mta-sts.{domain}:443 — {err}",
        ))

    # ── BIMI (bonus info) ────────────────────────────────────────────────────
    bimi_record = next((t for t in bimi_txts if "v=BIMI1" in t), None)
    if bimi_record:
        findings.append(Finding(
            category="bimi", status="pass",
            title="BIMI record present",
            detail=f"Brand logo will appear in supporting email clients.\n{bimi_record}",
        ))

    # ── No-email domain detection ─────────────────────────────────────────────
    # If the domain has no MX, no SPF, and no DMARC it almost certainly isn't
    # used for email. Show an informational note instead of an alarming F score.
    is_email_domain = bool(mx_hosts or spf_record or dmarc_record)
    if not is_email_domain:
        findings.insert(0, Finding(
            category="info", status="info",
            title="No email infrastructure detected",
            detail=(
                f"{domain} has no MX, SPF, or DMARC records. "
                "It doesn't appear to send or receive email. "
                "The findings below only become relevant if you intend to use this domain for email."
            ),
        ))

    score = min(100, score)
    grade, grade_color = _grade(score)

    fail_count = sum(1 for f in findings if f.status == "fail")
    warn_count = sum(1 for f in findings if f.status == "warn")

    if not is_email_domain:
        summary = f"{domain} has no email infrastructure — nothing to protect yet."
    elif fail_count == 0 and warn_count == 0:
        summary = f"{domain} has strong email security — no critical issues detected."
    elif fail_count == 0:
        summary = f"{domain} has a solid baseline but {warn_count} area{'s' if warn_count != 1 else ''} can be improved."
    elif fail_count >= 3:
        summary = f"{domain} has significant gaps — {fail_count} critical issues leave it exposed to phishing and interception."
    else:
        summary = f"{domain} has {fail_count} critical issue{'s' if fail_count != 1 else ''} that expose it to email-based attacks."

    return ScanResult(
        domain=domain,
        score=score,
        grade=grade,
        grade_color=grade_color,
        summary=summary,
        findings=findings,
        is_email_domain=is_email_domain,
        raw={
            "spf": spf_record,
            "dmarc": dmarc_record,
            "mx": mx_hosts,
            "mta_sts_txt": mta_sts_txt,
            "mta_sts_policy": mta_sts_policy,
            "cert": cert_info,
            "bimi": bimi_record,
        },
    )
