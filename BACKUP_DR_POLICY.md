# Backup & Disaster Recovery Policy

**Status as of this document: no automated backup or DR mechanism exists yet.**
This file is the policy and the gap list together — it documents the target,
and is honest about how far the current deployment is from it. Update the
"Current state" line under each section as work lands; don't let this file
drift into describing aspirations as facts.

## What's actually true today

- Database: PostgreSQL, accessed via `asyncpg` (see `app/config.py`'s `database_url`).
- Schema is fully versioned via Alembic (`backend/alembic/versions/`) — this is
  a real strength: a fresh environment can be brought to the correct schema
  state deterministically, which is half of disaster recovery.
- **No backup job, snapshot schedule, or `pg_dump` cron exists anywhere in
  this repo or its deployment config.** If the database disk is lost today,
  every domain, every DMARC/TLS report ever ingested, every user account,
  and every Stripe customer/subscription mapping is gone, permanently.
- No documented Recovery Time Objective (RTO) or Recovery Point Objective
  (RPO). Without these numbers, "do we have backups" can't even be answered
  meaningfully — a backup taken weekly with no other mechanism gives you an
  RPO of up to 7 days, which may or may not be acceptable; nobody has decided.

## Target policy

### Recovery objectives (placeholder — needs an explicit decision, not a default)
- **RPO:** how much data loss is acceptable in the worst case? For a security
  monitoring product, losing a day of DMARC ingestion is recoverable (the
  sending mail server still has the data; it'll just re-report next cycle).
  Losing a *user's account/billing state* is not similarly recoverable.
  Recommendation: 24-hour RPO for monitoring data, near-zero RPO for
  auth/billing tables specifically (these change rarely and matter most).
- **RTO:** how long can the product be down during a restore? Recommendation:
  under 4 hours for a single-region outage, pending actual infra decisions.

These two numbers should come from whoever owns the business relationship
with paying customers (MSP/Enterprise SLA commitments depend on them), not
be picked unilaterally by whoever sets up the first backup job.

### Backup mechanism
1. **If using a managed Postgres provider** (RDS, Cloud SQL, Azure Database
   for PostgreSQL, Neon, Supabase, etc.) — enable the provider's built-in
   automated daily snapshots plus point-in-time recovery (WAL-based), rather
   than rolling a custom `pg_dump` cron. This is almost always both cheaper
   and more reliable than a hand-rolled equivalent.
2. **If self-hosting Postgres** — `pg_dump` on a schedule (cron or the
   existing APScheduler instance in `main.py`, following the same pattern as
   the other background jobs) to a separate storage location (object storage
   in a different region/provider than the DB itself — a backup that lives
   on the same disk as the thing it backs up protects against nothing).
   Combine with WAL archiving for point-in-time recovery if the RPO target
   requires better than "since last nightly dump."
3. **Retention:** daily backups for 14 days, weekly for 90 days, is a
   reasonable starting point — adjust once real RPO/RTO targets are set.
4. **Test the restore, not just the backup.** A backup nobody has ever
   restored from is a hypothesis, not a recovery mechanism. Schedule a
   periodic (quarterly is reasonable) restore-to-a-scratch-environment drill.

### What's explicitly out of scope for "backup" but matters for DR
- **Stripe state** is the source of truth for billing, not this database —
  `Tenant.stripe_subscription_id` etc. are a cache. A DB restore should be
  followed by re-syncing from Stripe (the existing webhook handlers in
  `billing.py` already know how to do this reactively; a one-off
  reconciliation script that re-fetches each tenant's subscription state
  from the Stripe API directly would close the gap for anything that
  happened between the last backup and the incident).
- **Playwright/Chromium and other runtime dependencies** are not data and
  don't need backing up — they're reproducible from `requirements.txt` +
  `playwright install chromium`. Don't conflate "redeploy the app" with
  "recover the data"; they're different problems with different solutions.
- **SendGrid-sent emails** are not recoverable from this system if lost —
  they're fire-and-forget. This is acceptable; nobody expects to "restore"
  a sent email.

## Open decisions (need a person to decide, not code to assume)
- Who actually owns "is the backup running" as an ongoing operational
  responsibility — i.e., who gets paged if the nightly job fails silently?
- What hosting provider/region is production actually targeting? This
  document can't specify a concrete mechanism (RDS snapshots vs. a
  self-managed `pg_dump` cron) until that's settled.
- Formal RPO/RTO numbers, signed off by whoever sells the Enterprise SLA.
