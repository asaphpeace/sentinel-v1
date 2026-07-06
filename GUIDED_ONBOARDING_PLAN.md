# Guided Onboarding & Explainability Plan

Status: **approved direction, no code written yet.** This document is the
saved output of a brainstorming pass — research-grounded, competitor-checked,
options weighed — covering two related product goals:

1. Make publishing the DMARC/MTA-STS DNS records genuinely hand-holding for
   non-technical users, including discovering subdomains they didn't know
   they had.
2. Let users ask "why did this fail" about a DMARC/TLS source and get a
   clear, concise answer.

Both workstreams share a design principle already established elsewhere in
this codebase (see `recommendation_engine.py`'s split of deterministic rules
vs. AI explanation): **deterministic/structural answers come first and are
instant; AI is reserved for genuine follow-up, not the first response.**

---

## Part 1 — DNS publishing hand-holding (+ subdomain discovery)

### Why this matters
The current wizard generates the correct DNS record and shows it to the
user, then trusts them to go publish it correctly in their own DNS provider's
control panel. For a non-technical SMB owner, that's the single biggest drop-off
point in the entire onboarding flow.

### Competitive context (researched, not assumed)
- **Domain Connect** — open, free protocol. Redirects the user to their DNS
  provider, the provider shows a one-click consent screen, no credentials
  ever touch Sentinel. ~20 providers, ~35% of `.com` zone (GoDaddy,
  Cloudflare, Squarespace, WordPress.com, Google Workspace) — weak coverage
  for SA-specific registrars (Afrihost, Xneelo, Domains.co.za) and
  cPanel-based shared hosting, which is what this product's actual market
  runs on.
- **Entri** — commercial widget already integrated by **PowerDMARC,
  EasyDMARC, Mailjet, ClickFunnels**. Broader provider coverage (40+) via a
  mix of Domain Connect + direct registrar APIs + guided fallback, unified
  under one UI. Its absence is a concrete competitive gap against two direct
  competitors today, not a hypothetical one.
- Everyone else: static per-registrar text/screenshot guides. Highest
  maintenance burden, no automation.

### Phase 1 — build now, no third-party dependency
1. **Auto-detect the registrar/DNS provider** by resolving the domain's NS
   records and matching against known nameserver patterns. Sentinel already
   has the DNS resolution infrastructure (`dns_resolver.py`) — this is a
   pattern-match on data already being fetched, not a new capability.
2. **Curated, registrar-specific instructions** prioritising the providers
   this market actually uses — cPanel/WHM, Afrihost, Xneelo, Domains.co.za —
   not just the international giants the open standards already cover well.
3. **Live confirmation polling** — while the instructions are on screen, poll
   DNS every few seconds and flip to "✓ Detected!" the moment the record
   appears, instead of the user wondering if they did it right.
4. **"Email these instructions to whoever manages my website"** — one-click
   forward of the exact record + steps to a developer/IT contact, reusing
   `email_service.py` directly. Targets the real workflow of a non-technical
   owner who delegates DNS changes rather than learning DNS personally — not
   addressed by any competitor found in research.

### Phase 2 — bigger lever, evaluate once there's budget/data to justify it
- **Domain Connect first** (free, open standard, real engineering effort but
  no commercial dependency) — closes the gap for the highest-volume
  registrars.
- **Entri evaluated later** as a paid upgrade once revenue justifies the
  commercial integration — matches what two direct competitors already ship.
- Phase 1's guided flow remains the **permanent universal fallback** under
  both options — nobody is ever stuck regardless of registrar.

### Subdomain auto-discovery (folded into this workstream)

**Why it belongs here, not as a separate feature:** discovering a domain's
subdomains is most useful at exactly the moment a user is already in the
add-domain wizard — "we found these subdomains, want to bring them under
the same protection?" — and it directly feeds the `sp=` subdomain-policy
guidance already documented in the DMARC guide.

**Sources, ranked by fit for this product specifically (not a generic
recon/OSINT tool):**

1. **Certificate Transparency logs** (primary, free, no API key) — every
   publicly-trusted TLS cert since ~2018 is logged publicly with its SAN
   field. [crt.sh](https://crt.sh) is the standard free interface — no
   official rate limit, but can be slow or `502` under load (3–30s
   response times observed) — needs the same graceful-degradation handling
   the AI advisor already uses for LLM unavailability, never block the
   wizard on a slow CT query. **CertSpotter (SSLMate)** is a solid fallback
   source if crt.sh is unreachable.
2. **Mining Sentinel's own ingested DMARC data** (free, zero external calls,
   unique to this product) — `DmarcAggregate.header_from`/`envelope_from`
   already reveals which subdomains are actively *sending mail* for any
   domain currently monitored. Higher signal than CT logs for the question
   that actually matters here ("does this subdomain send mail and need its
   own alignment/`sp=` attention"), and no competitor found in research has
   this angle — it requires already being the system that ingests the
   reports.
3. **Certificate SAN fields Sentinel already stores** — `cert_service.py`
   already probes MX/HTTPS hosts and stores `SslCert.san`. Multi-SAN/wildcard
   certs often reveal sibling subdomains; this data already exists in the DB,
   just isn't currently parsed for this purpose.
4. **A short, bounded DNS check** — a curated list of email-relevant
   candidates (`mail`, `smtp`, `webmail`, `owa`, `autodiscover`, `mta-sts`,
   `mx`), resolved via existing DNS infra. Deliberately not a generic
   10,000-word brute-force — fast, polite, and scoped to what's actually
   relevant to email security.
5. **A one-line zone transfer (AXFR) attempt** — almost always refused by a
   correctly configured DNS server, free and instant to try, occasionally
   succeeds on a misconfigured one. Not relied upon, just a free bonus check.

**Deliberately excluded:** generic OSINT aggregators (SecurityTrails,
Shodan, Censys) and search-engine scraping — built for broad attack-surface
recon, require paid API keys for real coverage, and answer a different
question than "does this subdomain matter for email security."

**Gating — important, ties to an existing abuse surface:**
- Sources 1–3 (passive, public/already-owned data) are safe to run even
  before ownership verification — they're harmless to show during
  onboarding as a discovery moment.
- Source 4 (active DNS probing) must be **gated to ownership-verified
  domains only**, and specifically **not** exposed through the public,
  no-auth `/scan` endpoint beyond passive CT-log lookups. `/scan` is already
  rate-limited (10/min), but active subdomain probing on top of that would
  turn a public scanner into a free subdomain-enumeration tool against a
  domain the requester doesn't own.

**Output framing:** not a flat "12 subdomains found" list — specifically
surface which discovered subdomains are sending mail per DMARC data and have
no alignment of their own, since that's the actual decision this should
drive (the existing `sp=` subdomain-policy guidance), not generic recon.

---

## Part 2 — "Why did this fail" explainability

### Important precision on scope
DMARC *aggregate* reports (what Sentinel ingests today) contain counts per
sending source/IP/disposition, not individual message identifiers. "Why did
*this specific email* fail" is only answerable down to "why is *this
sending source* failing" — which is what matters operationally almost all
the time, but the UI/copy should say "source," not promise per-message
granularity the data can't deliver. Forensic (`ruf=`) reports, which do
carry per-message detail, aren't ingested — that's a separate, larger
decision (forensic reports contain message content samples — a
privacy/compliance surface of their own) and is out of scope here unless
explicitly requested later.

### What already exists — build on this, don't duplicate it
- `explain_auth_result()` (`dmarc_service.py`) — deterministic, instant,
  zero-cost lookup table covering common SPF/DKIM/alignment combinations.
- `SenderRecommendation` — auto-generated the moment a new sending source is
  seen, with a plain-English `recommendation` and concrete `dns_fix`,
  **already surfaced** in `DomainDetailView.vue` with dismiss functionality.
- `/advisor/chat` — general LLM chat grounded in live workspace data, scoped
  per screen.

### The actual gaps
- The whole `SenderRecommendation` pipeline is **DMARC-only** — TLS failures
  only have the static `explain_tls_failure()` table, no AI layer.
- It's **passive only** — auto-generated once per new source, no on-demand
  "ask about this" for sources already being looked at.
- **No entry point feels like asking a question** — no button anywhere says
  "explain this."

### Recommended build, in order
1. **An "Explain this" button on every source/record row, DMARC and TLS
   alike** — shows the existing deterministic explanation
   (`explain_auth_result`/`explain_tls_failure`) instantly, zero AI latency
   or cost, covers the common cases immediately.
2. **"Ask a follow-up"** beneath that — opens `/advisor/chat` pre-seeded with
   that row's exact data as context, so the AI elaborates on a specific
   situation rather than being asked to decide anything.
3. **Extend the existing auto-generation pipeline to TLS failures** — same
   "new source seen → generate an explanation automatically" pattern
   `dmarc_parser.py`'s `_bg_sender_recs` already runs for DMARC, applied to
   TLS failure reasons. Reuses existing generation/storage/dismiss
   machinery — the smallest-code-change way to close this gap.
4. **Explicitly deferred:** a free-text "ask about any email" search box.
   Flashier, but it's a fuzzier entry point into the same mechanism as #1 —
   build the reliable clickable version first, add search later only if
   users actually ask for it.

---

## Suggested sequencing

Resequenced to lead with the highest-leverage trust trio (Part 3, #9/#1/#2)
ahead of the original Parts 1–2 — these three directly attack the #1 reason
non-technical users abandon the advance-to-enforce journey, need no new
infrastructure (the underlying data already exists), and are independent of
the DNS/subdomain work below.

1. **Dry-run preview (#9)** — before "advance to reject," compute and show
   "0 legitimate sources would have been blocked" against the last 30 days
   of already-collected aggregate data. Strongest trust-builder, pure
   read-only computation on existing data.
2. **One-click rollback (#1)** — revert to the previous DNS record value the
   system already stored before the last advance. Pairs directly with #9:
   preview removes the fear of advancing, rollback removes the fear of
   having advanced.
3. **Dead-zone messaging (#2)** — explicit "we're listening now, first
   report typically arrives within 48 hours" state for the empty-dashboard
   period right after a record is published, instead of reading as broken.
4. Subdomain discovery, passive sources only (CT logs + own DMARC data +
   cert SANs) — cheapest of the remaining work, highest novelty, no
   third-party dependency, ships inside the existing wizard.
5. DNS hand-holding Phase 1 (registrar auto-detect, curated instructions,
   live polling, email-to-developer) — the biggest onboarding drop-off
   point, now backed by #1–#3 already softening the fear around it.
6. Explainability build, in the order listed in Part 2 (deterministic
   button → AI follow-up → extend to TLS).
7. **Vendor/stream auto-categorization (#19)** — rules-first lookup against
   known vendor SPF/DKIM signatures, AI only for the ambiguous remainder.
   Sequenced here because it reuses the same ingested-data surface as
   explainability (step 6) and meaningfully reduces the "is this legit"
   cognitive load the same way step 6 reduces "why did this fail."
8. Bounded active subdomain DNS check, gated to verified domains.
9. Remaining Part 3 items not already sequenced above — alerts
   plain-language pairing (#5), drift detection (#6), escalation path
   (#7/#16), score anchoring (#8), persistent progress indicator (#14),
   snooze state (#15) — roughly in that order, interleaved with whichever
   of 4–8 ships fastest since none of these depend on each other.
10. DNS hand-holding Phase 2 (Domain Connect, then Entri), scope-bumped per
    Part 4 to also cover SPF-flattening fixes — revisit once the above are
    shipped and there's usage data to justify the bigger lever.
11. Lowest-priority Part 3 items, pending the open decisions they need
    first: role-split business-summary view (#11), notification channel
    split (#10), value-anchored trial reminders (#13), streak framing
    (#17), worked-example wizard step (#18).
12. Part 4's deferred ideas (NL-query generated UI, cross-signal systemic
    correlation) — explicitly not scheduled; revisit only once step 6
    (explainability) and step 9's drift detection are live and there's
    real usage signal to justify either.

## Part 3 — beyond the wizard: workflow & trust gaps

Status: **identified, not yet scoped into build steps.** Found by auditing
the full lifecycle (not just the DNS-publish moment) for where a
non-technical user gets stuck, scared, or silently churns. Same design
principle as Parts 1–2: surface data the system mostly already has; new
infrastructure only where explicitly noted.

### Workflow / data gaps
1. **The "will this break my email?" fear is never directly addressed.**
   The biggest reason users stall at `p=none` forever. Needs: a plain-
   language "what could break and how you'd know" panel before every stage
   advance, plus one-click rollback to the previous DNS record (the system
   already knows the prior value).
2. **The dead zone between "record published" and "first data" has no
   hand-holding.** Aggregate reports take 24–48h+ to arrive; an empty
   dashboard reads as broken. Needs an explicit "we're listening now, first
   report typically arrives within 48 hours" state, distinct from empty/error.
3. **Jargon density outside the wizard.** SPF/DKIM/alignment/`p=quarantine`
   appear unexplained on overview, alerts, and the score breakdown. Needs a
   consistent inline-glossary pattern (hover/tap → one-line definition)
   applied app-wide, not just in Docs.
4. **No resumption path for an abandoned wizard.** Needs save-and-resume
   state, plus a reminder email after N hours of an incomplete domain.
5. **Alerts assume the reader knows what to do.** Every alert needs a paired
   "what this means" + "what to do" in the same plain language as the Part 2
   explainability work — same mechanism, not a separate one.
6. **No drift detection.** Nothing watches for someone else (a new IT
   contractor, a host "cleanup") silently breaking the published record
   months later. Needs an ongoing check that raises a distinct, urgent
   alert type — separate from normal compliance %.
7. **No human-escalation path inside the wizard.** Hand-holding has a
   ceiling. Needs a visible escalation path at the point of stuck-ness, not
   buried in account settings — directly useful for MSP positioning too.
8. **Score/grade shown with no anchor for "is that good?"** Needs
   contextual framing at the point the score is shown (e.g. "most
   businesses your size land between X–Y; here's what's pulling yours
   down") — reuses the recommendation engine's existing output.

### Trust / people gaps
9. **No sandbox/dry-run before an irreversible-feeling change.** The
   strongest trust-builder available: before "advance to reject," show
   "0 legitimate sources would have been blocked" computed against the last
   30 days of already-collected aggregate data.
10. **Notifications assume the owner reads email** — ironic for an email
    security tool, and the technical setup is often delegated to someone
    other than the risk-owner. Needs a designated "business owner contact"
    distinct from the login account, and a second channel (SMS/WhatsApp)
    reserved for severity-critical alerts only.
11. **No role split between "who set this up" and "who owns the risk."**
    Needs a stripped "business summary" mode (grade + one sentence + this
    month's report) vs. the full technical dashboard — same data, role-gated.
12. **Severity isn't visually tiered.** Without it, users either panic at
    routine notices or learn to ignore everything, including the drift
    alert from #6 that can't afford to be ignored. Needs a deliberate
    2–3 tier severity system in copy and visual treatment, applied
    everywhere once decided.
13. **Trial/plan expiry during incomplete setup has no value-anchored
    reminder.** Needs the reminder tied to concrete value already
    delivered ("we've been watching yourdomain.co.za for 12 days and
    caught 3 impersonation attempts — keep protection active").

### Interaction-pattern gaps (benchmarked against Google/Apple Security
Checkup, GitHub's security score, Stripe's onboarding checklist, Intercom,
banking fraud alerts)
14. **No single persistent progress indicator.** Security Checkup and
    Stripe both use one always-visible "X of Y complete" widget tying
    DMARC + MTA-STS + subdomains + verification into one bar. Sentinel has
    the data per-section but nothing unified surfaced persistently.
15. **No "snooze" state for recommendations/alerts** — currently
    accept-or-dismiss-forever. Dependabot and banking fraud alerts both use
    a third state ("not now, remind me in 2 weeks") for exactly the case
    where a user isn't ready to act but doesn't want to lose the item.
16. **Escalation (#7) works better as a live chat bubble than a ticket
    form** — Intercom-style, lower friction at the moment of highest
    frustration than a support form.
17. **No confidence-building "streak" framing during passive/waiting
    periods.** Consumer security apps reinforce trust during quiet periods
    ("Protected for 47 days straight") instead of showing nothing — pairs
    with #2's dead zone.
18. **No worked example shown before the real wizard step.**
    Typeform/Calendly-style flows show a filled-in example before asking
    the real question — reduces "what am I even looking for" at the DNS
    step specifically.

This audit is considered complete: items 1–8 are workflow/data gaps,
9–13 are trust/people gaps, 14–18 are interaction-pattern gaps borrowed
from platforms that solve this exact category of problem well. Anything
past this starts becoming generic SaaS UX advice rather than something
specific to this product's hand-holding problem.

---

## Part 4 — AI-native dashboard patterns (benchmarked against current
industry direction for DMARC/TLSRPT specifically, not generic chat UX)

Status: **one new item approved for the backlog; two ideas explicitly
deferred pending demand evidence; two patterns confirmed as already
covered by Parts 1–3.**

### Already built — verified, not a gap
19. **Vendor/stream auto-categorization.** ~~Add to backlog~~ — checked the
    code: `source_classifier.py` already does exactly this. Rule-based
    classifier (`authorized` / `forwarded` / `unauth` / `spoof`) against
    known-ESP regex patterns (Google, Microsoft 365, Mailgun, SendGrid,
    HubSpot, Salesforce, etc.), DKIM/SPF alignment signals, and abuse-ASN/
    Tor-exit detection, with a confidence score and a plain-language reason
    per source — feeding `DmarcAggregate.classification` and the dry-run
    simulation built in step 1 below. No AI layer for the ambiguous
    remainder yet (falls back to a generic "Review needed" at 50%
    confidence) — that gap is real but small; revisit only if the
    "unknown" bucket turns out to be a large share of real traffic once
    this is in front of users.

### Build log
- **Step 1 (dry-run preview, #9) — done.** `simulate_advance()` in
  `recommendation_engine.py` (pure function, 6 unit tests), endpoint
  `GET /domains/{id}/simulate-policy`, surfaced as "Preview impact before
  advancing" in `RoadmapTrack.vue`. Reuses the same `fail_count`/
  classification data the recommendation engine already computes — no new
  data source needed.
  **Correction (found during audit):** the UI's "based on the last 30 days
  of data" claim was false at first ship — `_dmarc_sources()` summed
  all-time `DmarcAggregate` history with no `period_begin` filter, while
  every other DMARC time-window query in the codebase (`overview.py`,
  `advisor.py`) correctly applies one. Fixed by adding a `since` parameter
  (`_SOURCE_WINDOW_DAYS = 30`) threaded through `build_domain_input()`,
  with a regression test (`test_recommendation_data.py`) locking in that an
  aggregate older than the window is excluded. This also fixed the
  `_evaluate_dmarc()` regression gate, which shared the same unwindowed
  query — a source that failed months ago and was since fixed could have
  blocked a stage advance forever.
- **Step 2 (rollback, #1) — done, plus a related gap closed along the way.**
  Found that `dns_records` already stores a full previous/current value
  change log (`DnsRecord`, used by the existing DNS Timeline page) — so
  "rollback" needed no new data model, just a "Revert: copy this" button on
  the previous-value diff line in `TimelineEntry.vue` (DMARC/MTA-STS/TLS-RPT
  only — copies the prior value to the clipboard with the exact host to
  paste it back into). While in that code: found `is_security_alert` was
  already computed for the timeline display but never raised an actual
  alert — drift (#6) was detected but silent unless someone happened to
  visit the DNS Timeline page. Closed that gap too in `dns_service.py`'s
  `_record_change()`, since rollback without a proactive warning that
  something changed is much less useful. Domain Connect/Entri (writing the
  reverted value back to the provider automatically) remains future work —
  this is the manual-but-effortless version the current architecture
  supports today.
- **Step 3 (dead-zone messaging, #2) — done.** New `DataDeadZone.vue`
  component replaces the flat "No report data yet" text in `DmarcView.vue`
  and `MtaStsView.vue` with four distinct states: no record published yet
  (CTA to Roadmap), within the normal 24–48h arrival window ("we're
  listening now," reassuring), past 48h but under a week (quieter, no
  urgency), and genuinely overdue at 7+ days (different message —
  suggests checking the reporting address, since that's a real possible
  cause at that point, not just "wait longer"). Uses `domain.added_at` as
  the publish-time proxy since the exact record-publish timestamp isn't
  separately tracked — accurate enough for elapsed-time framing, not
  pretending to more precision than the data supports.
- **Step 4 (passive subdomain discovery) — done.** New
  `subdomain_discovery_service.py` implements all three passive sources
  exactly as scoped: own DMARC data (`DmarcAggregate.header_from`, zero
  external calls, the highest-signal source since it tells you what
  actually sends mail), certificate SANs (`SslCert.san`, already collected
  by `cert_service.py`), and CT logs via crt.sh (degrades to empty on
  timeout/502, never blocks). Endpoint `GET /domains/{id}/discover-
  subdomains`, surfaced as a "Scan for subdomains" card in
  `DomainDetailView.vue` — mail-sending subdomains sort first per the
  plan's framing note ("not a flat list"), each with a one-click "Monitor
  this" action that reuses the existing wizard start/confirm flow rather
  than a new domain-creation path. 6 unit tests on the hostname-matching
  logic (lookalike-domain and sibling-domain false-positive cases
  specifically). Active DNS probing (source #4) intentionally not built —
  remains gated to verified domains as a separate, later step.
- **Step 5 (DNS hand-holding Phase 1) — done.** New `registrar_service.py`
  auto-detects the registrar from NS records (9 curated providers,
  SA-market-first — Afrihost, Xneelo, Domains.co.za, cPanel/WHM ahead of
  the international giants — generic fallback never errors). Three new
  endpoints: `GET /domains/{id}/registrar-instructions`,
  `GET /domains/{id}/check-dns-live` (cheap, no-DB-write, built specifically
  for polling every few seconds — distinct from the heavier `/sync-dns`),
  and `POST /domains/{id}/email-instructions` (renders the exact record +
  registrar steps server-side so the recipient needs no Sentinel login —
  the delegated-setup case the plan flagged as unaddressed by any
  competitor found in research). All three wired into the existing
  `RecordReviewModal.vue` — already shared by the DMARC, MTA-STS, and
  Roadmap review flows, so this lands in all three at once: a collapsible
  step-by-step panel, an "Email these instructions" form, and live
  ✓-Detected polling (capped at 10 minutes, stops silently rather than
  polling forever if the modal is left open). 7 unit tests on the pure
  matching logic, including the lookalike/unknown-nameserver fallback
  case. Domain Connect/Entri (Phase 2) remains separate, later work — this
  is the permanent universal fallback the plan calls for regardless.
- **Step 6 (explainability) — done, all three build items.** Found item 1
  ("Explain this" button) was already further along than the plan assumed
  — `explain_auth_result()`/`explain_tls_failure()` are already inline in
  `DmarcAuthDrawer.vue`'s verdict banner and `MtaStsView.vue`'s MX rows, not
  gated behind a click at all (exceeds the original ask). The two real
  gaps were items 2 and 3:
  - **Item 2 ("Ask a follow-up")** — `/advisor/chat` existed server-side
    but had zero frontend caller. Built `AskFollowUp.vue`, a small
    reusable inline chat thread that seeds its first message with the
    exact row's data (IP/org/DKIM/SPF detail for DMARC, MX
    host/failure/session-counts for TLS) so the AI elaborates on a
    specific situation rather than starting from nothing. Wired into both
    `DmarcAuthDrawer.vue` and `MtaStsView.vue`.
  - **Item 3 (extend auto-generation to TLS)** — new
    `generate_tls_recommendation()` mirrors `generate_sender_recommendation()`'s
    output shape exactly, so it reuses `SenderRecommendation`'s existing
    storage/dismiss/display machinery untouched (classification=
    `tls_issue`, zero migration). Hooked into `tls_parser.py` the same way
    `dmarc_parser.py` already hooks DMARC — a background task fires once
    per new (MX host, failure reason) pair. Deliberately rule-based only,
    no AI elaboration call: RFC 8460 failure reasons are a fixed,
    well-understood enum, unlike DMARC sending sources which need
    judgment calls about unfamiliar orgs.
  - Free-text search remains explicitly deferred, as planned.
  10 new unit tests across both items (TLS recommendation generation +
  the existing pure-function pattern), all passing.
- **Step 8 (bounded active subdomain check, gated to verified domains) —
  done.** Extended `subdomain_discovery_service.py` (built in step 4) with
  the two active sources from Part 1's source #4: a 10-candidate
  email-relevant wordlist check (`mail`, `smtp`, `webmail`, `owa`,
  `autodiscover`, `mta-sts`, `mx`, `imap`, `pop`, `exchange` — deliberately
  not a generic brute-force list) and a one-line AXFR zone-transfer
  attempt (almost always refused, free to try, runs off the event loop via
  `asyncio.to_thread` since dnspython's transfer API is synchronous). Both
  gated behind a new `allow_active` parameter that the router only sets
  `True` when `domain.ownership_verified` — confirmed `/scan` (the public,
  no-auth endpoint) doesn't reference this service at all, so the gating
  the plan called out as load-bearing is structurally enforced, not just
  documented. 2 new tests specifically guard the gate: `allow_active`
  defaults to `False` (so a future caller that forgets to pass it
  explicitly doesn't get active probing by accident), and the candidate
  list is asserted to stay short — a regression test against this quietly
  growing into a real brute-force list over time.
- **Step 9 (remaining Part 3 items) — done, 4 of 5 sub-items** (#6 drift
  detection was already closed in step 2; folded the rest in here):
  - **#5 (alerts paired "what this means" + "what to do")** — added
    `Alert.action` as a real column, separate from `body`, via migration
    `a9b8c7d6e5f4` (also added `sender_recommendations.snoozed_until` in
    the same migration for #15 below). Populated at all 3 existing
    `Alert(...)` call sites (drift, recommendation engine, cert expiry) —
    each now states the factual outcome in `body` and the concrete next
    step in `action`, instead of one mixed paragraph. `AlertMenu.vue`
    renders them as two visually distinct lines.
  - **#15 (snooze state)** — new
    `POST /domains/{id}/dmarc/sender-recommendations/{rec_id}/snooze`
    (defaults to 14 days, 1-90 range), and the existing recommendations
    list endpoint now hides anything snoozed-but-not-yet-due without
    losing it — it reappears unchanged once the snooze elapses. Wired into
    `DomainDetailView.vue`'s Sender Actions cards as "Not now — remind me
    in 2 weeks" alongside the existing Dismiss button.
  - **#8 (score anchoring)** — deliberately did NOT add the plan's literal
    suggested copy ("most businesses your size score X") since Sentinel
    has no real peer-benchmark dataset to back that claim, and a
    fabricated statistic would be worse than none. Instead, `SentinelRing.vue`
    now derives and shows "N pts available in <pillar>" — the single
    biggest score-pulling-down pillar, computed honestly from the same
    breakdown numbers already displayed, right under the score where it's
    seen first instead of only in the portfolio table far below.
  - **#14 (persistent progress indicator)** — `AppTopbar.vue` now shows an
    always-visible "{n} / {total} protected" pill (DMARC at reject AND
    MTA-STS at enforce) on every page, clickable through to the Roadmap —
    closes the gap where setup status was only visible on whichever page
    happened to be open.
  - **#7/#16 (escalation path)** — added a plain mailto link ("Still stuck?
    Email Sentinel support") inside `RecordReviewModal.vue`'s hand-holding
    panel, following the existing `mailto:sales@...` pattern already used
    in `BillingView.vue`. Deliberately not a live chat widget — that
    remains the open cost/build decision the plan already flagged; this is
    the honest version of "talk to a human" the current architecture
    actually supports without a new third-party dependency.

### Confirmed already covered — no new work
- **DNS what-if simulation** → already Part 3 item #9 (sequencing step 1).
  External validation that it's the right first move, nothing to add.
- **One-click DNS deployment via provider API** → already Domain Connect
  (Part 1, Phase 2). Scope bump: extend it to cover SPF-flattening fixes
  too (when a record exceeds the 10-lookup limit), not just the initial
  DMARC/MTA-STS record — small addition to existing scope, not a new item.

### Promising, explicitly deferred — not promised for v1
- **Intent-driven NL query → generated custom UI** (e.g. "show me why my
  transactional subdomains failed SPF yesterday" rendering a tailored
  geo-map + alignment grid + live SPF comparison, not just a text answer).
  `/advisor/chat` already answers in text; a per-query *generated view* is
  a materially bigger lift. Scope as an enhancement to Part 2's "ask a
  follow-up" step only after the simpler click-to-explain ships and there's
  real signal on what people actually ask — don't build the generative
  layer speculatively.
- **Cross-signal systemic correlation** (e.g. "this TLS spike correlates
  with your DNS provider's serial update 2 hours ago"). Directionally
  right and a real differentiator, but needs sustained historical signal
  density per domain — an SMB with low mail volume won't have enough data
  points for the correlation to be reliable, and a false "this caused
  that" claim is worse than no claim. Scope as a deeper-diagnosis layer on
  top of drift detection (#6) once that's live and has real data to
  correlate against, not a standalone build.

---

## Open decisions (need a person, not code)
- Budget/timeline for Domain Connect engineering effort vs. waiting for
  Entri to become commercially justifiable.
- Whether forensic (`ruf=`) report ingestion is ever wanted, given the
  privacy/compliance surface it opens — not assumed here either way.
- Curated registrar list for Phase 1's instructions — needs real data on
  which DNS providers this market's actual customers use, not a guess.
- Severity-tiering scheme (#12) and the SMS/WhatsApp channel choice (#10)
  need a decision before either is built — not a default to guess at.
- Whether a live chat bubble (#16) means a third-party tool (Intercom,
  Crisp) or a lighter in-house widget — cost/build tradeoff, not assumed.
