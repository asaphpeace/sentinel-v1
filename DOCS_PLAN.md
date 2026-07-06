# Sentinel V1 — Documentation Plan

## Structure
Docs live inside the app at `/docs` as a single-page view with a left-hand section nav and rendered markdown content. No external hosting needed — everything stays within Sentinel.

---

## Section 1 — Getting Started
**Audience:** New user or MSP onboarding a client for the first time.
- What Sentinel is and what it protects against (DMARC spoofing + MTA-STS downgrade attacks)
- Adding your first domain — what the `<slug>@foundationcraft.co.za` reporting address is and why it's needed
- Understanding your first Sentinel Score — what the grade means, what drives it up
- Connecting DMARC reports — how long until data starts appearing

## Section 2 — DMARC Implementation Guide
**Audience:** IT admin working through the policy advancement journey.
- The four stages: p=none → quarantine → reject, plus what BIMI unlocks at the end
- How to read the DMARC Analytics page — compliance rate, source table, fail reasons
- SPF alignment explained — envelope-from vs header-from, why they must match
- DKIM setup per major ESP (Google Workspace, Microsoft 365, Mailchimp, HubSpot, SendGrid, Salesforce, Mailgun) — exact steps
- The SPF 10-lookup limit — what it is, how to diagnose it, how to flatten with macros
- When to advance policy — the 95% / 30-day gate explained
- Subdomain policy gaps — sp= tag and when to use it

## Section 3 — MTA-STS & TLS Guide
**Audience:** IT admin starting or advancing the inbound TLS track.
- What MTA-STS protects against and why it matters even after DMARC is at p=reject
- The three components: policy file (HTTPS), DNS TXT record, TLS-RPT
- Testing mode vs enforce mode — what changes, what the risks are
- How to read the TLS posture page — pass rate, failure breakdown by MX host
- Common blockers: missing STARTTLS, cert hostname mismatch, shared hosting MX
- Safe advancement checklist: what to verify before flipping to enforce

## Section 4 — Certificates Reference
**Audience:** Infrastructure engineer managing MX hosts.
- Why certificate health is critical in MTA-STS enforce mode
- Certificate statuses explained: ok / expiring_soon / critical / expired / error
- What a hostname mismatch means and how to fix it (SAN vs CN)
- Deprecated TLS versions (v1.0/1.1) — risk and remediation
- STARTTLS: what it is, how to verify it's enabled on your MX host
- Recommended renewal cadence (60-day reminder, renew at 30 days)

## Section 5 — DNS Timeline Guide
**Audience:** IT admin or MSP monitoring DNS changes.
- What the DNS Timeline audits and why it matters
- Severity levels: info / warn / critical — what each means
- Common critical events: DMARC record removed, SPF modified to +all, policy downgraded
- How to investigate a critical change — correlate with change management records
- Setting up a regular DNS audit cadence

## Section 6 — MSP Guide
**Audience:** MSP engineers managing multiple client tenants.
- Multi-tenant architecture — how tenants are separated
- Adding and managing client accounts
- The white-label PDF report — how to generate it, what it contains, how to brand it
- Portfolio view explained — reading posture across all domains at once
- Bulk onboarding workflow — adding multiple domains efficiently
- Pricing and plan limits per tier

## Section 7 — API Reference
**Audience:** Developer or MSP building integrations.
- Authentication — JWT token flow, how to obtain and refresh tokens
- Core endpoints: domains, DMARC data, TLS data, certificates, advisor, reports
- Webhook events (if applicable)
- Rate limits and error codes
- Example: pulling a domain's Sentinel Score via API

## Section 8 — Sentinel Score Reference
**Audience:** Anyone interpreting the score or explaining it to a client.
- How the score is calculated — DMARC weight, MTA-STS weight, certificate health weight
- Grade bands: A (90–100), B (75–89), C (60–74), D (45–59), F (<45)
- What moves the score up vs down
- Using the score in client reports

---

## Implementation approach
Each section is a structured markdown file rendered inside `DocsView.vue`. The view gets a collapsible left nav for sections and a content pane with anchor links. The Sentinel Advisor is available in the chat panel on the docs page. Content is written in the same voice as the Advisor — expert, direct, no filler — targeting an IT admin who knows DNS but may be new to email authentication.
