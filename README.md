# Sentinel

Email security posture platform — DMARC, MTA-STS/TLS-RPT, and certificate
monitoring with a single composite score, an AI advisor, MSP multi-tenancy,
and a rule-based recommendation engine that gates enforcement advancement
behind real compliance/volume/regression checks instead of a static
checklist.

This document is the project's living memory: what's built, why it's built
the way it is, and what's deliberately not built yet. Update it as
architecture decisions change — don't let it drift into describing
aspirations as facts (see [`BACKUP_DR_POLICY.md`](BACKUP_DR_POLICY.md) for
the same discipline applied to that document).

## Positioning

Target buyer is MSP-first: the wedge is the self-service SMB IT manager (2–10
domains), the revenue driver is the MSP managing 10–80 client domains under
one account, pricing is in ZAR. Direct competitor at the SMB level is
Sendmarc (DMARC-only, no MTA-STS, no portfolio scoring); at the MSP level
there is no direct local competitor. Full reasoning and the pricing table
live in project memory, not duplicated here to avoid drift between two
sources of truth.

## Architecture

```
backend/   FastAPI + async SQLAlchemy + PostgreSQL + Alembic
frontend/  Vue 3 + TypeScript + Pinia + Vite
e2e/       Playwright end-to-end tests against the running app
```

### Backend

```
app/
  main.py              FastAPI app, CORS, rate limiter, request-ID middleware,
                        APScheduler background jobs
  config.py            All settings (pydantic-settings, env-driven)
  database.py          Async engine/session factory
  logging_config.py    JSON structured logging, per-request correlation ID
  rate_limit.py         shared slowapi Limiter (own module — avoids a circular
                        import between main.py and the routers that use it)
  models/              SQLAlchemy ORM models, one file per domain concept
  schemas/             Pydantic request/response models
  services/            Business logic — routers stay thin, call into these
  routers/             FastAPI route definitions
alembic/versions/      Linear migration history, no branches
```

**Routers**: `auth`, `domains`, `dmarc`, `tls`, `overview`, `certs`, `dns`,
`alerts`, `advisor`, `scan` (public, no-auth domain scanner), `billing`,
`msp`, `audit`.

**Services worth knowing about specifically:**
- `recommendation_engine.py` — pure functions, zero I/O, zero LLM. Takes a
  `DomainRecommendationInput` dataclass, returns `Recommendation` objects
  with an explicit `direction` (`advance` / `hold` / `regression`). This is
  intentional: a tool that tells someone to enforce `p=reject` and breaks
  their mail is a real cost, so the *decision* is deterministic and
  unit-tested (`tests/test_recommendation_engine.py`, 14 cases, zero DB). An
  LLM only ever explains a decision this module already made — it doesn't
  make the decision.
- `recommendation_data.py` — the only thing that touches a DB session for
  recommendations; builds the engine's input from real `DmarcReport`/
  `DmarcAggregate`/`TlsReport`/`SslCert` rows. Split out specifically so the
  engine above can stay pure and DB-free.
- `recommendation_service.py` — runs the engine per domain, persists only
  `ADVANCE`/`REGRESSION` outcomes as `Alert` rows (not `HOLD` — surfacing
  "still not ready" every day would train users to ignore the bell). Same
  rule set also drives the PDF report's recommendation list and the Roadmap
  page's "why can't I advance yet" panel — one source of truth, not three.
- `pdf_report_service.py` — renders the report to an actual PDF via
  Playwright + headless Chromium. WeasyPrint was tried first (pure Python,
  no browser) but needs native GTK/Pango libraries with no clean Windows
  install path. The HTML built here is self-contained — it doesn't navigate
  to the live frontend — so PDF generation works identically for a manual
  download or an unattended background job.
- `email_service.py` — SendGrid's REST API called directly via `httpx` (no
  SDK dependency). If `SENDGRID_API_KEY` is unset, emails are logged instead
  of sent — nothing in this codebase requires a real key to run or to test.
- `audit_service.py` — explicit logging calls at ~15 known mutation points
  (invites, role changes, 2FA, password changes, domain lifecycle, plan
  changes, MSP client lifecycle), not a generic request-logging middleware.
  A middleware gets you "PATCH /domains/abc123" in the log; explicit calls
  get you "advanced example.com from quarantine to reject" — readable by a
  non-engineer, and a reviewer can verify the list of call sites is complete
  by reading a short list, not by trusting route-pattern matching.

### Frontend

```
src/
  views/        One component per route (DocsView, RoadmapView, BillingView, …)
  components/   Reusable UI, organized by domain (wizard/, domain/, layout/, ui/)
  stores/       Pinia — auth, domains, ui
  api/client.ts  Single typed fetch wrapper; every backend call goes through it
  router/        Route table + the requiresAuth guard
```

Login/registration/password-reset/email-verification/accept-invite all live
in `LoginView.vue` / dedicated views reachable without authentication —
see `router/index.ts` for which routes are public vs. behind the
`requiresAuth` guard.

## Key architectural decisions (and why)

**Per-tenant email uniqueness, not global.** `User.email` used to be
globally unique. That breaks the moment SSO exists: the same corporate
email can legitimately be an SSO identity in two unrelated tenants (e.g. an
MSP's own staff member). Current model: `UniqueConstraint(tenant_id, email)`
always enforced, plus a Postgres **partial** unique index,
`ix_users_email_password_unique`, scoped to `WHERE auth_method = 'password'`
— so password accounts stay globally unique (no duplicate self-registration
across tenants) while SSO accounts can share an email across tenants. Login
filters on `auth_method = 'password'` explicitly so the lookup stays
unambiguous despite the relaxed constraint. Migration:
`d4e5f6a7b8c9_sso_ready_user_identity.py` (plus a same-day follow-up,
`e5f6a7b8c9d0`, fixing a leftover unique index the first migration missed —
see its docstring for the exact mechanism).

**Report ingestion has DB-level idempotency**, not just an application-level
check. `dmarc_reports`/`tls_reports` have a partial unique index on
`(domain_id, report_id) WHERE report_id != ''`. This was added after finding
*actual* duplicate rows in a real environment — the IMAP poller had no
idempotency check at all, and a domain's compliance %/Sentinel Score had
been silently inflated by exactly the duplicate factor (verified: 6x on
DMARC, 5x on TLS for the affected domain) until the fix landed. See
`a7b8c9d0e1f2_report_ingestion_idempotency.py` for the dedup-then-constrain
migration.

**Deleting a domain renames it, not just deactivates it.** `domains.name`
carries a *global* unique constraint (one tenant can monitor a domain at a
time, by design). Soft-deleting via `is_active=False` alone left the name
permanently squatted — nobody, including the original tenant under a
different account, could ever re-add it. `delete_domain` now renames the
row to `name~deleted~<id>` on delete, releasing the literal name while
preserving history (everything else references `domain_id`, not `name`).

**JWT revocation via a version counter, not a blacklist.** Tokens are
stateless by design (no DB lookup per request). `User.token_version` is
embedded in every issued token as `tv` and checked in `get_current_user`;
bumping it (on password change, password reset, 2FA enable/disable)
instantly invalidates every previously-issued token for that user with one
column write, no blacklist table, no per-request DB hit beyond what already
happens. A token with no `tv` claim (issued before this feature existed) is
accepted once — it ages out naturally within its normal expiry rather than
retroactively logging out every active session on deploy day.

**Audit log entries never reference a tenant/user that's about to be
deleted.** `audit_log_entries.tenant_id`/`actor_user_id` are real foreign
keys with `ON DELETE CASCADE`/`SET NULL`. Two places this matters: deleting
your own tenant (`auth.py`'s `delete_account`) logs to the application
logger instead of the DB, since a DB row describing "tenant deleted" would
cascade-delete in the same transaction it's recording; deleting an MSP
client tenant logs against the *MSP's own* tenant_id, not the client's that's
about to disappear.

**Rate limiting is selective, not blanket.** `slowapi`, applied only to
`/auth/token` (10/min), `/auth/forgot-password` (5/min), and the public
`/scan` endpoint (10/min) — the actual abuse surface. Everything else sits
behind a JWT already. One real gotcha hit while wiring this up: `slowapi`'s
decorator wrapper breaks Pydantic's forward-ref resolution in any file using
`from __future__ import annotations` (see the comment at the top of
`scan.py`) — the wrapper's `__globals__` don't include the module's own
names. Fix was removing that import from the one file that didn't actually
need it, not avoiding the rate limiter.

**Structured JSON logging with per-request correlation**, via a
`ContextVar` rather than threading a request ID through every function
signature by hand (`logging_config.py`). Background jobs (the APScheduler
jobs in `main.py`) run outside any request, so their log lines simply have
no `request_id` — that's expected, not a gap; they're correlated by job
name and timestamp instead.

**MSP client tenants can self-upgrade independently** (a deliberate decision,
not a default) — a client tenant's own admin can check out their own Stripe
subscription, fully independent of the MSP's pooled plan; nothing in
`billing.py` special-cases `parent_tenant_id`. This is verified to already
work structurally with no code changes needed for the checkout/webhook path
itself. The one real gap it opened: `msp.py`'s `delete_client` used to
delete the tenant row with no check for an active subscription — harmless
before this decision (clients could never have had a real one), a genuine
billing bug after. Fixed via a shared `cancel_tenant_subscription()` helper
used by both `delete_client` and the existing downgrade-to-free path in
`change_plan`.

## What's real vs. what's a plan-page promise

Built and verified end-to-end against the real app (not just import checks):
DMARC/MTA-STS/cert monitoring, the Sentinel Score, the rule-based
recommendation engine, MSP multi-tenancy with white-label reports, Stripe
billing (checkout/webhooks/portal), 2FA, audit log (Enterprise-gated),
scheduled PDF report delivery, password reset, email verification, ToS
acceptance, data export, bulk domain import via file upload, structured
logging, a public no-auth domain scanner.

**Deliberately deferred, not forgotten:**
- **SAML SSO** — the schema groundwork (`auth_method`, per-tenant
  uniqueness) is done; the actual `python3-saml` integration, JIT
  provisioning, and admin IdP-config UI need a real IdP to test against
  safely, not a guess.
- **BIMI** — referenced in the public scanner and the docs, but no VMC/logo
  upload flow exists. Needs a product decision on that flow before it's a
  coding task.
- **A written backup/DR mechanism** — the *policy* is written
  ([`BACKUP_DR_POLICY.md`](BACKUP_DR_POLICY.md)), but it documents that no
  automated backup job actually exists yet, and is explicit about which
  decisions (RPO/RTO numbers, hosting provider) need a person, not code.

## Running it

### Backend
```
cd backend
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # not a pip package — needed for PDF report generation
cp .env.example .env          # fill in at minimum DATABASE_URL
alembic upgrade head
uvicorn app.main:app --reload
```

### Frontend
```
cd frontend
npm install
npm run dev
```

### Tests
```
cd backend
# Requires a Postgres test DB — defaults to sentinel_test on localhost.
# Override with TEST_DATABASE_URL if your local Postgres uses different
# credentials than the dev DB (see tests/conftest.py's module docstring).
TEST_DATABASE_URL=postgresql+asyncpg://USER:PASS@localhost:5432/sentinel_test \
  pytest tests/ -q
```
99 tests as of this writing — pure unit tests for the recommendation engine
(zero DB, runs in milliseconds), integration tests against a real Postgres
instance for everything else (`tests/conftest.py`'s `client`/`db_session`/
`auth_client` fixtures, SAVEPOINT-isolated so tests never leak state into
each other). See `tests/factories.py` for the model factories — extend
these rather than constructing ORM objects by hand in new tests.

Frontend has its own Vitest unit tests (`frontend/src/__tests__`, run via
`npm test`) and Playwright E2E tests against the running app (`e2e/`,
separate from the backend's use of Playwright for PDF rendering — same
library, two unrelated purposes).

## Database migrations

Linear history, no branches, in `backend/alembic/versions/`. Notable recent
ones (newest first): `f2a3b4c5d6e7` terms acceptance, `e1f2a3b4c5d6`
scheduled report preferences, `d0e1f2a3b4c5` token revocation,
`c9d0e1f2a3b4` email verification, `b8c9d0e1f2a3` password reset,
`a7b8c9d0e1f2` report-ingestion idempotency (the data-corruption fix —
read its docstring), `d4e5f6a7b8c9` + `e5f6a7b8c9d0` SSO-ready identity
(two migrations because the first one missed a leftover index — see
`e5f6a7b8c9d0`'s docstring for exactly what it fixes and why).

Run `alembic upgrade head` after pulling any change that touches
`app/models/`. Never edit an already-applied migration in place — add a
new one, even to fix a mistake in the previous one (see the
`d4e5f6a7b8c9`/`e5f6a7b8c9d0` pair for the precedent).
