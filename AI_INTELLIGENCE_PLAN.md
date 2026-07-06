# Sentinel AI Intelligence Layer — Revised Implementation Plan
**Updated: 2026-06-18**

## Goal
Make Sentinel feel like an intelligent platform, not a dashboard with a chatbot.
AI must be *visibly present* at the right moments — not overwhelming, not hidden.

## The Sweet Spot Rule
> Show AI output **once per view**, **above the fold**, in plain English.
> Never show more than one AI-generated block on the same screen at the same time.
> Always show a timestamp and provenance badge so the user knows it's AI, not a formula.

---

## SHARED FOUNDATION (build first, used by all steps)

### F1 — `AiBadge` component
`frontend/src/components/ui/AiBadge.vue`
- Tiny chip: `✦ Sentinel AI · <timestamp>` in `--teal` on dark pill background
- Props: `timestamp: string`, `loading: boolean`
- Loading state: animated pulse (same CSS as existing loading skeletons)
- Used on every AI-generated block across the platform

### F2 — `AiNarrativeCard` component
`frontend/src/components/ui/AiNarrativeCard.vue`
- Full-width dark card (`background: rgba(255,255,255,0.03)`, `border: 1px solid rgba(46,230,197,0.15)`)
- Slots: `<AiBadge>` top-right, paragraph body, optional action row
- Loading skeleton: 3 shimmer lines
- Fallback state: renders rule-based text in muted style (no badge — signals it's not AI)
- This is the **only** AI prose container used platform-wide (no one-off styling)

---

## STEP 1 — Executive Narrative Engine

### What
AI-generated 3-paragraph executive summary rendered in two places:
1. **Overview page** — as the first card below the score ring (replaces the current static advisor panel)
2. **PDF Report** — first section of the report (above the data tables)

### Why first
Data is already assembled. Highest MSP value. Sets the visual language for all later steps.

### Backend
- New function in `advisor_service.py`: `generate_report_narrative(report_data: dict) -> str`
- Input: score, score_delta, dmarc_compliance_pct, threat_count, cert_warnings, period_days, top_risk
- Ollama prompt → 3 short paragraphs: period summary / threat narrative / next action
- Temperature=0, max_tokens=280, JSON output `{ "summary": "...", "threats": "...", "actions": "..." }`
- Rule-based fallback: template strings using the same input fields
- New column: `sentinel_snapshots.narrative TEXT` (Alembic migration)
- Trigger: called at end of existing snapshot job (not in request path)
- New endpoint field: `GET /overview/report-data` returns `narrative: { summary, threats, actions, generated_at }`

### Frontend
- `OverviewView.vue`: replace current `advisor` block with `<AiNarrativeCard>` showing the 3 paragraphs
- `ReportView.vue`: render narrative at top of report before data tables
- Both use the shared `AiNarrativeCard` + `AiBadge` components

### Files changed
`advisor_service.py`, `routers/overview.py`, `models/snapshot.py`, alembic migration,
`OverviewView.vue`, `ReportView.vue`, + 2 new shared components

---

## STEP 2 — DNS Change Risk Assessment

### What
When DNS poller detects a record change, auto-generate a risk badge on that row in DNS Timeline.
No new page. AI surfaces *inline* on existing data — the minimum footprint for maximum signal.

### Backend
- Post-insert hook in `dns_service.py` after writing to `dns_records`
- Sends: record_type, previous_value, current_value, current SPF/DMARC context
- Ollama output: `{ severity: "info|warn|critical", explanation: "...", action: "..." }`
- Stored in existing `alerts` table: `category='dns_change'`, `narration=JSON output`
- Rule-based fallback: severity inferred from record type (DMARC policy change → warn, TXT addition → info)

### Frontend — DNS Timeline view
- Each changed row gets a severity pill: green/amber/red dot + label
- Clicking the row expands an inline drawer showing the AI explanation + recommended action
- `<AiBadge>` inside the drawer — provenance visible but not dominant
- No new page, no new nav item

### Files changed
`dns_service.py`, `advisor_service.py`, `DnsTimelineView.vue`

---

## STEP 3 — Intelligent Sender Onboarding

### What
When a new sending source appears in DMARC aggregates, auto-classify it and generate the exact DNS fix.
Surfaced as an **action queue** in Domain Detail — not alerts, not a notification — a to-do list.

### Backend
- After `dmarc_parser.py` rebuilds aggregates, compare source_orgs to previous period
- New sources → Ollama: `{ classification: "known_esp|unknown|suspicious", dns_fix: "...", confidence: 0-1 }`
- Rule-based fallback: classify by ASN lookup against known ESP ranges (Mailchimp, SendGrid, etc.)
- New model: `sender_recommendations (domain_id, source_org, source_ip, classification, dns_fix, created_at, dismissed_at)`
- New migration

### Frontend — Domain Detail view
- New "Sender Actions" section at the bottom of `DomainDetailView.vue`
- Shows pending recommendations as action cards: org name, classification chip, exact DNS record to add, Dismiss button
- `<AiBadge>` on each card — but subdued (smaller, muted) since this is a list, not a headline
- Badge only shown for AI-classified items; rule-based fallbacks show no badge

### Files changed
`dmarc_parser.py`, `advisor_service.py`, `DomainDetailView.vue`,
new `models/sender_recommendation.py`, migration

---

## STEP 4 — Policy Promotion Simulation

### What
Before the user moves DMARC from `none→quarantine` or `quarantine→reject`, show them the blast radius.
One button, one modal, one verdict. AI translates the numbers into a plain-English recommendation.

### Backend
- New endpoint: `POST /domains/{id}/dmarc/simulate-promotion`
- Queries last 30 days of `dmarc_aggregates`, calculates % of legitimate mail that would be blocked
- Sends summary to Ollama: `{ safe_to_promote: bool, collateral_pct: float, explanation: "...", fixes: ["..."] }`
- Rule-based fallback: return numbers only, no prose — frontend renders a neutral verdict instead
- Response on demand (not stored — computed fresh each time since it's user-triggered)

### Frontend — DMARC view
- "Simulate upgrade" button appears on domains at `none` or `quarantine` stage
- Clicking opens a modal: loading → result card
- Result card: large `safe_to_promote` verdict (green checkmark or amber warning), collateral %, explanation paragraph, list of fixes
- `<AiBadge>` in the result card header
- If no AI (fallback): show numbers only, no badge, neutral label "Analysis"

### Files changed
`routers/dmarc.py`, `advisor_service.py`, `DmarcView.vue`

---

## WHAT WE ARE NOT BUILDING (anti-overwhelm decisions)

| Rejected idea | Why |
|---|---|
| Floating "Ask Sentinel" chat button | Chatbot framing — exactly what we're avoiding |
| Intelligence tab in sidebar | Too much dedicated surface area before Step 6 has enough data to fill it |
| Platform threat counter in header | Deferred to Step 6 — header real estate is valuable, don't occupy it with a zero |
| AI output on every view simultaneously | Sweet spot rule: one AI block per view, above the fold |
| Streaming AI responses | Adds complexity, creates "chatbot feel" — store then display |
| AI confidence percentages visible to user | Confusing for non-technical users — use severity labels instead |

---

## REVISED STEP 5 — Smart Alert Correlation (unchanged from original)
Group related alerts on same domain within 48h into a single Incident with AI narrative.
Surface in Overview as "Incidents" section above the alert list.
*(Implement after Steps 1–4 are live and generating data.)*

## REVISED STEP 6 — Cross-Tenant Threat Intelligence (unchanged from original)
Network-effect moat. IPs failing across ≥3 tenants → platform threat feed.
At this point, add the platform threat counter to the header bar — by then it will show real numbers.
*(Implement last — requires scale.)*

---

## Architecture Rules (unchanged)
1. Ollama is NEVER in the user request path — all AI runs in background or on-demand with a spinner
2. Every Ollama call: temperature=0, max 300 tokens, JSON schema enforced
3. Every feature has a rule-based fallback (Ollama down = degraded gracefully, not broken)
4. All background AI output stored in DB — never re-generated on page load
5. `AiNarrativeCard` + `AiBadge` are the only AI UI primitives — no one-off styling

## Tech Stack Reference
- Backend: FastAPI + async SQLAlchemy + PostgreSQL + APScheduler
- Frontend: Vue 3 + TypeScript + Pinia + Vue Router
- AI: Ollama (local, http://localhost:11434, model=llama3)
- Design tokens: --bg:#06060f --teal:#2ee6c5 --indigo:#5b6ef5 --good:#34e0a1 --warn:#f5c542 --bad:#ff4d6d
- Venv: backend/.venv/Scripts/
- Frontend port: 5173, Backend port: 8000

## Session Notes
- Always restart backend after model/schema changes
- Run alembic migrations: `.venv\Scripts\alembic upgrade head`
- Frontend hot-reloads automatically
- `sentinel_session` localStorage key persists plan/role across refreshes
