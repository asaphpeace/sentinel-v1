import logging
import uuid
from contextlib import asynccontextmanager

import asyncio

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.logging_config import configure_logging, request_id_var
from app.rate_limit import limiter
from app.routers import auth, domains, dmarc, tls, overview, certs, dns, alerts, advisor, scan, billing, msp, audit, platforms, mta_sts_hosting, concepts, service, cloud, engagement

# Applied selectively (see auth.py's login/forgot-password, scan.py's
# scan_domain) — the abuse surface here is brute-forcing /auth/token,
# enumerating accounts via /auth/forgot-password, and scraping/DDoS-ing the
# public no-auth /scan endpoint. Everything else sits behind a JWT, so a
# blanket rate limit on every route would add cost without addressing the
# actual risk.

configure_logging()
log = logging.getLogger(__name__)

def _make_interval_task(fn, seconds: int):
    async def _loop():
        while True:
            await asyncio.sleep(seconds)
            await fn()
    return _loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [
        asyncio.create_task(_make_interval_task(_imap_poll_job, settings.imap_poll_interval)()),
        asyncio.create_task(_make_interval_task(_cert_probe_job, settings.cert_probe_interval)()),
        asyncio.create_task(_make_interval_task(_dns_poll_job, settings.dns_poll_interval)()),
        asyncio.create_task(_make_interval_task(_recommendation_job, settings.recommendation_interval)()),
        asyncio.create_task(_make_interval_task(_scheduled_report_job, settings.scheduled_report_check_interval)()),
    ]
    log.info("Sentinel background scheduler started")
    yield
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _imap_poll_job():
    try:
        from app.services.imap_service import poll_inbox
        await poll_inbox()
    except Exception:
        log.exception("IMAP poll job failed")


async def _cert_probe_job():
    try:
        from app.services.cert_service import probe_all_domains
        await probe_all_domains()
    except Exception:
        log.exception("Cert probe job failed")


async def _dns_poll_job():
    try:
        from app.services.dns_service import poll_all_domains
        await poll_all_domains()
    except Exception:
        log.exception("DNS poll job failed")


async def _recommendation_job():
    try:
        from app.services.recommendation_service import evaluate_all_domains
        await evaluate_all_domains()
    except Exception:
        log.exception("Recommendation evaluation job failed")


async def _scheduled_report_job():
    try:
        from app.services.scheduled_report_service import send_scheduled_reports
        await send_scheduled_reports()
    except Exception:
        log.exception("Scheduled report job failed")


app = FastAPI(
    title="Sentinel API",
    description="DMARC · MTA-STS · SSL monitoring platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Generates a request ID (or reuses one from an upstream reverse proxy via
    X-Request-Id) and makes it available to every log line emitted while
    handling this request, via the ContextVar in logging_config.py — no need
    to thread it through every function signature by hand.
    """
    incoming = request.headers.get("x-request-id")
    request_id = incoming or str(uuid.uuid4())
    token = request_id_var.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-Id"] = request_id
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(dmarc.router)
app.include_router(tls.router)
app.include_router(overview.router)
app.include_router(certs.router)
app.include_router(dns.router)
app.include_router(alerts.router)
app.include_router(advisor.router)
app.include_router(scan.router)
app.include_router(billing.router)
app.include_router(msp.router)
app.include_router(audit.router)
app.include_router(platforms.catalog_router)
app.include_router(platforms.router)
app.include_router(mta_sts_hosting.public_router)
app.include_router(mta_sts_hosting.router)
app.include_router(concepts.router)
app.include_router(service.router)
app.include_router(cloud.router)
app.include_router(engagement.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
