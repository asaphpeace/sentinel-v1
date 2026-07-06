# Pain Point Resolution Plan

Status: **plan only, no code written.** This document is written directly
against your own Mimecast MSE experience — the ad-hoc SPF/DKIM meetings,
the training calls, the "why isn't this aligning" tickets, the enforcement
fear, the subdomain blind spot. The verdict on the current build is taken
seriously: the pieces that exist (registrar detection, source
classification, dry-run simulation, subdomain discovery) are real
infrastructure, but they don't yet *add up* to "nobody needs a meeting
with you to fix this." This plan is about closing that gap completely, not
polishing what's there.

Each section: the pain restated in your words, an honest audit of what
exists today against it, why that's not enough, and the creative fix.

## Self-audit: where the first draft of this plan fell short

Before building on it, this plan was checked back against the original
ask and three real gaps were found and corrected here — not nuances,
verifiable misses:

1. **Mimecast — named explicitly as a pain-point example, not actually
   recognized anywhere.** Grepped the entire backend: Mimecast appears
   exactly once, in an unrelated code comment about MX certificate
   hostname mismatches, never in the actual sending-source classification
   (`source_classifier.py`'s `KNOWN_ESPS`, `verdict_service.py`'s
   `_KNOWN_ESPS` — neither lists it). The first draft of this plan said
   the new platform library should "start from" that same list — which
   would have silently carried the gap forward. **Fixed below**: Mimecast
   is now an explicit, separate v1 platform-profile entry, not assumed
   covered by inheritance from a list that was checked and doesn't
   include it.
2. **"Registrar and nameservers will need to be exposed" — nameservers
   weren't exposed anywhere in the UI.** Checked: `registrar_service.py`'s
   `detect_registrar()` already returns the resolved nameservers
   (`RegistrarInstructionsOut.nameservers`), but grepping every frontend
   file that renders registrar info, that field is never displayed.
   **Fixed below**: a "Detected DNS infrastructure" panel is now part of
   the hand-holding flow.
3. **TLS's "same challenges, but more of them" wasn't mapped 1:1 against
   each DMARC pain — some genuinely don't transfer, but that reasoning was
   never stated.** **Fixed below**: an explicit mapping table.

A fourth point raised directly during review: **MX host validation must
use SMTP+STARTTLS, never HTTP** — already correctly built in
`cert_service.py` (MX hosts probe port 25 with STARTTLS; the
`mta-sts.<domain>` host probes port 443 as real HTTPS, no STARTTLS). This
plan adds a managed-hosting piece and a per-MX scorecard that both touch
this code path — the constraint is called out explicitly wherever it's
relevant below so neither addition can blur it.

---

## Pain 1 — The ad-hoc SPF/DKIM meeting, multiplied by every sending platform × every DNS provider

### What exists today
- `source_classifier.py` / `verdict_service.py` recognize ~25 ESPs from
  envelope/rDNS patterns and produce a generic classification (authorized,
  forwarded, unauth, spoof) with a one-line `dns_fix` string like "Add the
  SendGrid SPF include to your TXT record."
- `registrar_service.py` has step-by-step DNS publishing instructions for
  9 DNS providers (Afrihost, Xneelo, cPanel, Cloudflare, GoDaddy, etc.) —
  but only for the DMARC/MTA-STS/TLS-RPT records themselves, not for a
  *platform's* SPF include or DKIM CNAME.

### Why that's not enough
These two systems never talk to each other. A customer gets told "add a
SendGrid SPF include" (the what) and separately "here's how to add a TXT
record on Afrihost" (the how, for a different record entirely) — but never
the actual combined answer: *exactly which record, with exactly which
value, added exactly where, for this specific platform on this specific
DNS provider.* That gap is precisely the meeting. A generic `dns_fix`
string assumes the customer already knows what an SPF include syntax
looks like and where their ESP's DKIM CNAMEs are published — which is the
whole reason the meeting happened in the first place.

### The fix — a Sending Platform Library, multiplied against the registrar library
A new structured knowledge set, `platform_profiles/`, one entry per
sending platform. **v1 list, checked individually rather than inherited
wholesale from the existing classifier** (see the self-audit above —
`_KNOWN_ESPS` was checked and confirmed to be missing Mimecast, so it's
listed as a verified gap to close, not assumed covered):

- **Mimecast** (outbound relay/gateway) — explicitly added; absent from
  every existing classification list despite being the platform named
  first in the pain that started this plan.
- SendGrid, Mailchimp, Microsoft 365, Google Workspace, HubSpot,
  Salesforce Marketing Cloud, Klaviyo, Zendesk, Postmark, SparkPost,
  Amazon SES, Mailgun, Constant Contact, ActiveCampaign, Pardot, Marketo,
  Zoho — these *do* already appear in `verdict_service.py`'s
  `_KNOWN_ESPS` or `source_classifier.py`'s `KNOWN_ESPS`, confirmed by
  reading both lists directly, not assumed.

The v1 cutoff beyond this set is an open decision below — you have direct
knowledge of which platforms actually generated meetings most often, and
that should set it, not a guess at "common ESPs."

Each profile carries:
- The exact SPF mechanism (`include:sendgrid.net`, IP ranges where
  relevant) and whether it's a single include or grows with multiple
  sending domains (Microsoft 365 in particular needs this called out —
  customers very often don't know they need `include:spf.protection.outlook.com`
  *and* on-prem connector IPs if hybrid).
- The DKIM setup mechanism: CNAME-based (most ESPs hand you 2-3 CNAMEs
  pointing at their signing infrastructure) vs. copy-paste TXT key, with
  the platform's actual selector naming convention.
- Where in that platform's own admin UI this is configured (menu path,
  not a generic "check your settings") — this is maintained as structured
  text now; a later phase can add screenshots once there's real customer
  usage data on which platforms matter most.
- The custom/branded return-path mechanism if the platform supports one
  (directly closes Pain 3's envelope-mismatch scenario — see below).
- Known gotchas specific to that platform (e.g. "SendGrid's default setup
  signs with their own domain until you complete domain authentication in
  their dashboard — DKIM will show as unaligned `esp_unauth` until that's
  done, this isn't a Sentinel detection bug").

**The multiplication that actually kills the meeting:** when a sending
source is classified as a recognized platform, the fix card shown is no
longer a generic sentence — it's the platform profile's exact SPF/DKIM
values **combined with the customer's already-detected registrar**
(reusing `registrar_service.py`'s `detect_registrar()` and step list
verbatim). The customer sees: "Add this exact TXT record. Here's exactly
how, on Afrihost, where you already publish your other records." Same
"Email these instructions" and live-polling confirmation patterns already
built for the DNS hand-holding flow apply unchanged — this is new content
flowing through existing mechanisms, not new infrastructure.

**Proactive, not just reactive:** add a "Which platforms do you send mail
through?" multi-select step to the onboarding wizard, parallel to the DNS
step. A customer who declares SendGrid + Microsoft 365 before any DMARC
data even exists gets both setup cards immediately — closing the gap
where today nothing happens until a real aggregate report reveals the
platform days later. This is the single highest-leverage change for
killing the meeting before it would have happened.

**Expose the registrar detection itself, not just its output — closing
the verified nameserver gap.** `detect_registrar()` already resolves and
returns the nameservers it used to identify the provider
(`RegistrarInstructionsOut.nameservers`); the fix is surfacing that data,
not computing anything new. Add a small "Detected DNS infrastructure"
line to the hand-holding panel: `Nameservers: ns1.afrihost.co.za,
ns2.afrihost.co.za → matched to Afrihost`. Two reasons this matters beyond
transparency: (1) when detection *fails* and falls back to generic
instructions, showing the actual nameservers it saw ("we found
`ns1.somehost.net` / `ns2.somehost.net` and didn't recognize this
provider") turns a dead end into something a customer can act on
themselves — paste it into a search, or hand it to you/support directly
instead of a meeting starting from zero; (2) it's the same fact pattern
you'd have asked for first in the old meetings ("what are your
nameservers") — making it visible by default removes a back-and-forth
question, not just a mystery.

---

## Pain 2 — Onboarding was a training session (alignment, compliance, authentication, return-path)

### What exists today
`DocsView.vue` has static documentation sections. The AI advisor exists
but answers questions, it doesn't *teach* unprompted, and a brand-new user
has no reason to know which question to ask about a term they've never
heard.

### Why that's not enough
Static docs require the user to already suspect they're missing a concept
and go look it up — that's not how the training sessions worked. You
taught alignment *at the moment* a customer was looking at a real
authentication failure and asked "why is this red," using their own data
as the example. A docs page divorced from that moment doesn't replace
that.

### The fix — Concept Cards, seeded with the user's own data, exactly where confusion happens
Not a separate course. A small, dismissible "?" affordance attached to
every term that caused real confusion in your meetings — *alignment*,
*compliance*, *envelope-from / return-path*, *authentication* — appearing
inline next to the first place that term is used on screen (the
compliance %, the alignment badges in `DmarcAuthDrawer.vue`, the
header-from/envelope-from fields). Clicking it doesn't open a generic
glossary entry — it opens a short explanation **rendered with the
customer's own current values substituted in**: "Alignment means the
domain that authenticated this message (`spf_domain`) matches the domain
your recipients see (`header_from`). For `{their actual header_from}`,
SPF authenticated `{their actual spf_domain}` — that's why this row shows
unaligned." This reuses the same `select_facts()` / knowledge-layer
pattern just built for the AI advisor (`app/knowledge/`), just rendered as
an inline card instead of a chat reply, with the live row's data spliced
into the fact's statement template instead of generic prose.

Track per-user which concept ids have been shown (`concepts_seen` on the
user or a small table) so the cards fade out for someone who's clearly
learned the term, but never disappear entirely — there's always a "?" to
revisit.

**A second, bigger piece this enables almost for free:** since
`generate_tls_recommendation`/`generate_sender_recommendation` and the
knowledge layer already produce grounded, cited explanations, a per-domain
"Explain my setup" page can auto-generate a short, personalized writeup —
*this domain's* alignment status, *this domain's* compliance trend, in
plain language, citing the same concept cards — which an MSP can literally
send to a non-technical stakeholder instead of holding the training call.
This is the PDF report's spirit applied to education instead of just
scoring.

---

## Pain 3 — "Why isn't source X aligning" (envelope mismatch / foreign DKIM / signature broken in transit)

### What exists today
This is the pain point closest to actually solved. `verdict_service.py`'s
`compute_verdict()` already names envelope mismatch (`esp_bounce`/
`esp_unauth`), foreign DKIM (covered under the same envelope-mismatch
branch when `dkim_domain` is foreign), and DKIM signature failure
(`auth_failure`, with the explanation already saying "key may have been
rotated or the message was modified in transit"). This is real,
already-built diagnostic depth — more than the audit gave it credit for
initially.

### Why that's not enough
Two specific gaps, both named directly in your pain points:
1. **"Modified in transit" vs. "key mismatch" are lumped into one
   sentence** — `auth_failure`'s explanation covers both possibilities at
   once instead of distinguishing them, when these have different fixes
   (a forwarder/mailing-list modifying in transit is often *unfixable*
   from the sending side; a rotated key is a five-minute DNS fix). A
   customer told both at once is back to needing you to explain which one
   actually applies to them.
2. **No platform-specific remediation attached** — the verdict says "add
   DKIM signing" but doesn't connect to Pain 1's platform library to say
   *how*, for *this* platform.

### The fix — split the DKIM-fail diagnosis, and wire it to the platform library
Extend `verdict_service.py`'s `dr == "fail"` branch into a real
sub-classifier rather than one sentence:
- **Likely transit modification**: the sending source's rDNS/envelope
  pattern matches known mailing-list/forwarder signatures (reuse and
  extend the forwarder detection already in `source_classifier.py`'s
  `classification == "forwarded"` path) — surface as "This looks like a
  forwarder or mailing list modified the message after it was signed,
  which breaks DKIM by design. This is usually not fixable from your side
  unless the forwarder supports ARC sealing — check whether {known
  forwarder} offers that."
- **Likely key/selector mismatch**: no forwarder signal present — surface
  as "The DKIM signature failed without an obvious forwarding cause —
  verify the public key at `{selector}._domainkey.{dkim_domain}` matches
  what {platform, if recognized} currently has configured. Keys rotate
  periodically; this is the most common cause when alignment previously
  worked." Where the source is a recognized platform, append that
  platform's exact "find your current DKIM key" admin path from the
  library.

This isn't a guess dressed up as certainty — both branches say what
evidence led to that conclusion, consistent with the existing "rules
decide, AI explains" principle, and the AI advisor's `select_facts()`
mechanism can elaborate further on request via the existing
`AskFollowUp.vue` pattern.

---

## Pain 4 — Unclear indicators for when to enforce a policy

### What exists today
`recommendation_engine.py` gates advancement on aggregate compliance %,
days collected, and "no significant authorized sender currently failing."
The dry-run simulation (`simulate_advance()`) shows aggregate impact.
Both are real, working, and already a step ahead of "just watch the
number go up."

### Why that's not enough
The indicator is a single aggregate number and a pass/fail gate — it
doesn't show *which specific sources* are the reason, in one place, with
their fix already linked. A customer (or you, in the old meetings)
shouldn't have to cross-reference the Sending Sources table against the
Roadmap page to build that picture themselves.

### The fix — a per-source Readiness Scorecard, not just an aggregate gate
A new view (or a new card on the existing Roadmap page) listing every
significant sending source with three states, computed directly from data
the engine already has: **Ready** (aligned, passing), **Blocking**
(failing, with its specific fix card from Pain 1/3 inline), **Below
volume floor** (intentionally not gating, shown for transparency). This
turns "should I enforce" from a single score into a literal checklist:
"7 of 8 sources ready. SendGrid is blocking — here's its fix." That
checklist *is* the enforcement indicator, in language a customer can act
on without you.

Also fold in a **stability indicator** the current gate doesn't have:
compliance held steady for the gate's required window vs. compliance that
recently spiked — a domain at 96% for 25 of its last 30 days reads
differently than one that hit 96% only in the last 2. This is a small,
real addition to `recommendation_data.py`'s window logic, not a new
subsystem.

---

## Pain 5 — Same problems, worse, for TLS/MTA-STS (low adoption)

### Explicit mapping — does each DMARC pain actually transfer to TLS?
The first draft of this plan jumped straight to the hosting bug without
stating this reasoning — here it is explicitly, per pain, rather than
silently addressing some and skipping others:

| DMARC pain | Transfers to TLS? | Why |
|---|---|---|
| Different sending platforms × DNS provider (Pain 1) | **No, structurally** | TLS/MTA-STS governs *inbound* mail to the domain's own MX hosts — there's no equivalent of "which ESP did you send through," because the customer isn't sending through anything here. The DNS-provider hand-holding axis still applies (publishing the MTA-STS/TLS-RPT records) and is covered below. |
| Training-call concepts (Pain 2) | **Yes** | STARTTLS vs. MTA-STS vs. TLS-RPT, testing vs. enforce mode — addressed below with Concept Cards, same mechanism as DMARC. |
| Why isn't source X aligning (Pain 3) | **Partially** | TLS has no "alignment" concept at all (that's DMARC-specific), but it has the equivalent ambiguity question: why did this MX host fail TLS. `FAILURE_REASONS` in `tls_service.py` already maps to fairly unambiguous RFC 8460 result-type codes (`certificate-expired`, `starttls-not-supported`, etc.) — these don't carry the same one-code-two-causes problem DKIM's `fail` result does, so the DKIM-style sub-classification split is **not needed here**; the existing per-code explanations are already specific enough. What *is* missing is the platform-style remediation depth — covered below. |
| Enforcement indicators (Pain 4) | **Yes** | Mirrored below as a per-MX-host scorecard. |
| Subdomains invisible at enforce time (Pain 6) | **Yes, and more acute** | A subdomain can have its own MX records and its own MTA-STS posture entirely separate from the parent — the Disposition Ledger (below) must check TLS readiness per subdomain too, not just DMARC. |

### A real bug found while planning this, worth fixing regardless of the rest
`wizard_tls_info()` currently generates the MTA-STS policy URL as
`{mta_sts_base_url}/{domain}/.well-known/mta-sts.txt` — e.g.
`https://mta-sts.foundationcraft.co.za/customerdomain.com/.well-known/mta-sts.txt`.
**This cannot work.** Per RFC 8461, a sender validating MTA-STS for
`customerdomain.com` looks up `mta-sts.customerdomain.com` directly and
fetches the policy from exactly that hostname — there is no mechanism by
which it would ever construct a URL on `foundationcraft.co.za`. Every
customer who has gone through this flow has a policy that will never
actually be fetched by a real sender. This needs fixing regardless of
anything else in this plan.

### The fix, and the bigger opportunity it unlocks
The correct, and far more valuable, fix: **Sentinel hosts the policy
file directly at the customer's own `mta-sts.<domain>` hostname**, via one
CNAME record (`mta-sts.customerdomain.com → mta-sts-host.sentinel.app`,
analogous to how CDNs and managed-cert services already work) plus
automatic per-domain TLS certificate provisioning (ACME/Let's Encrypt,
DNS or HTTP-01 challenge) for that exact hostname server-side. This
removes the single biggest reason MTA-STS adoption is low industry-wide:
**you need to run your own HTTPS server just to publish a policy file.**
A customer who can publish a DNS TXT record can now do MTA-STS exactly
the same way they already do DMARC — one DNS hand-holding flow, reusing
the same registrar library, with no separate hosting requirement at all.
This is a genuine differentiator, not just a bug fix.

**Protocol-boundary note, raised directly during review and worth being
explicit about so it can't get blurred while building this:** the
`mta-sts.<domain>` hostname this section hosts is a genuine HTTPS
endpoint — RFC 8461 mandates the policy be fetched via HTTPS GET, so the
ACME certificate provisioning above (HTTP-01 or DNS-01 challenge) is
correctly a normal web-TLS operation. This is a completely different
protocol surface from validating the customer's actual **MX hosts**,
which only ever speak SMTP — those can never be checked over HTTP and
must go through STARTTLS (port 25), exactly as `cert_service.py`'s
`_probe_tls(host, 25, starttls=True)` already does today, correctly. The
managed-hosting piece adds a new HTTPS-serving endpoint; it must never be
used as a substitute for, or confused with, the existing STARTTLS-based MX
probing that feeds the scorecard below — they answer different questions
("can senders fetch your policy" vs. "do your mail servers actually speak
TLS correctly") and both matter independently.

### The rest of the TLS gap, mirroring DMARC's treatment
- A **per-MX-host Readiness Scorecard**, mirroring Pain 4's DMARC version
  — which MX hosts are TLS-clean vs. which are blocking enforce, with
  cert health folded in (`cert_service.py` data already exists, just
  needs joining into one view instead of a separate page). This scorecard
  is built entirely from the existing STARTTLS-based probe data
  (`SslCert` rows where `host_type == "mx"`) — never from an HTTP check
  against the MX hostname, which would silently produce meaningless
  results (most MX hosts run no web server at all on port 443).
- **Concept Cards for TLS-specific terms** (STARTTLS vs. MTA-STS vs.
  TLS-RPT, opportunistic vs. enforced) — same mechanism as Pain 2, since
  low adoption is partly a low-*understanding* problem, not only a
  tooling gap.
- The existing `tls.policy_caching` knowledge fact (senders cache a
  fetched policy, so a change doesn't take effect everywhere instantly)
  needs to be surfaced proactively the moment a policy is published, not
  left for the advisor to mention only if asked — this is exactly the
  kind of thing that generated confused follow-up calls.

---

## Pain 6 — Sending subdomains invisible to admins until enforce time

### What exists today
Passive subdomain discovery (CT logs, own DMARC data, cert SANs) plus a
bounded active check for verified domains — built and working, surfaced
on the Domains page and folded into the DMARC view by sending domain.

### Why that's not enough
Discovery alone is passive — a subdomain can be *found* and just sit
there unacknowledged. Nothing stops a domain from reaching "ready to
enforce" while a discovered, mail-sending subdomain has never been looked
at. That's exactly the scenario that bit people at enforce time: a
subdomain nobody remembered existed suddenly has its mail blocked.

### The fix — a Subdomain Disposition Ledger that gates enforcement, not just informs it
Every discovered subdomain that sends mail must have an explicit
disposition before the domain it belongs to can show as enforcement-ready:
**Monitor it** (added as its own domain, or explicitly tracked), **Exclude
it** (explicitly, with a required one-line reason — "decommissioned,"
"intentionally third-party," etc. — stored, not silently ignored), or
**Inherited** (covered by an `sp=` policy that's been deliberately set,
not just defaulted). This is a small new table
(`subdomain_dispositions`) and one new rule in `recommendation_engine.py`:
a mail-sending subdomain with no disposition on record is a **HOLD**
blocker on the parent domain's advancement, with the blocking reason
naming the exact subdomain. No more silent gaps — the gate makes the
omission impossible to miss, the same way the dry-run simulation already
makes "would this break mail" impossible to miss.

---

## Suggested build order

1. **MTA-STS hosting fix** (Pain 5) — it's a real bug independent of
   everything else here, and the CNAME-based managed hosting redesign is
   foundational to several other TLS improvements in this plan.
2. **Sending Platform Library (incl. the verified Mimecast gap) +
   onboarding declaration step + nameserver-exposure panel** (Pain 1) —
   the highest-leverage fix for the literal pain that started this
   conversation, including both gaps the self-audit found.
3. **Subdomain Disposition Ledger gate** (Pain 6) — small, self-contained,
   closes a real safety gap.
4. **DKIM-fail sub-classification + platform-linked remediation**
   (Pain 3) — builds directly on step 2's library.
5. **Per-source/per-MX Readiness Scorecards** (Pain 4 + 5) — ties steps
   2-4 together into the "should I enforce" answer. The per-MX side must
   be built strictly from existing STARTTLS-probe data, never a new
   HTTP-based check against MX hosts (see Pain 5's protocol-boundary note).
6. **Concept Cards** (Pain 2) — can build in parallel with any of the
   above once the knowledge-layer rendering pattern is decided.

## Open decisions (need you, not code)

- **Platform library scope beyond v1's confirmed set** (Mimecast +
  the ~17 platforms already verified present in `_KNOWN_ESPS`/
  `KNOWN_ESPS`): you have direct knowledge of which other platforms
  actually generated meetings most often — that should set the next
  additions, not a guess at "common ESPs."
- **MTA-STS managed hosting**: this requires Sentinel to provision and
  renew TLS certificates per customer domain and proxy/serve policy
  content per-domain — real infrastructure (ACME client, per-domain cert
  storage, a hosting endpoint), not a config change. Worth confirming
  this is the direction before scoping the build in detail.
- **Subdomain exclusion reasons**: whether excluded subdomains should ever
  expire/re-prompt (e.g. "still excluding `old.example.com` after 12
  months — still correct?") or stay excluded indefinitely once dispositioned.

---

# Implementation Plan — concrete UI surfaces (buttons, modals, wizard steps)

Every fix above is specified here as an actual screen, button, or modal —
not an abstract "the system will surface this." Existing component names
are used where something is extended; new component names are proposed
where something doesn't exist yet. No code written yet — this is the
exact shape the build will take.

## Pain 1 — Sending Platform Library

**New wizard step — `WizardStepPlatforms.vue`**, inserted into
`AddDomainWizard.vue` between `WizardStep1Domains.vue` and
`WizardStep2Dmarc.vue`.
- A grid of platform tiles (Mimecast, SendGrid, Microsoft 365, Google
  Workspace, Mailchimp, HubSpot, Salesforce Marketing Cloud, Klaviyo,
  Zendesk, Postmark, SparkPost, Amazon SES, Mailgun, Constant Contact,
  ActiveCampaign, Pardot, Marketo, Zoho) — click to multi-select.
- A **"+ Other platform"** tile opens a small inline text field — stored
  as an unrecognized-platform flag so it surfaces later for you to see
  which undeclared platforms real customers actually use (direct signal
  for the open "scope beyond v1" decision).
- A **"Skip — detect automatically"** button bypasses the step entirely;
  nothing here blocks the existing flow.
- **Continue** button persists selections and immediately creates a
  pending setup card for each (no DMARC data needed yet — this is what
  makes it proactive instead of reactive).

**New modal — `PlatformSetupModal.vue`** (props: `domainId`, `platformKey`,
optional `sourceRecommendationId`). Triggered from four places:
1. A **"Set up now"** button that appears under each tile selected in
   `WizardStepPlatforms.vue`.
2. A new **"Fix this"** button added to every non-authorized row in
   `SourceTable.vue` (next to the existing classification chip).
3. A clicked cell in the new Platform Health Matrix (below).
4. A new **"+ Add a sending platform"** button on `DomainDetailView.vue`
   (and on the Platform Health Matrix itself) — opens the *same*
   platform-tile picker used in `WizardStepPlatforms.vue`, so an
   already-onboarded domain isn't locked out of proactive declaration just
   because it's past the wizard. Without this, only brand-new domains ever
   get the proactive flow — every existing customer stays reactive-only,
   which defeats the point.

Contents: a DKIM section (exact CNAME/TXT values + copy button, "Where to
configure this in {platform}" steps, "Open {platform} →" link), and an
**SPF status strip** — not a standalone "add this record" instruction.
Adding SPF here routes into the shared SPF Composition Builder below
rather than proposing an isolated record, because the modal's job for one
platform must never overwrite what another platform already needs. Footer:
**Mark as done** (with a confirm step — "DNS hasn't detected this yet, mark
as done anyway?" — if the live check hasn't actually passed, so an
unconfirmed setup can't be silently waved through), **Email these
instructions**, **Close**.

**New shared component — `SpfCompositionBuilder.vue`**, embedded inside
`PlatformSetupModal.vue`'s SPF section and also reachable standalone from
`PlatformHealthMatrix.vue`. This is the actual answer to "what should my
SPF record say" — it always shows the **one, full, merged record**
covering every declared + detected platform at once, recomputed live as
platforms are added or removed, with a running count against the 10-DNS-
lookup limit (`dmarc.spf_lookup_limit`) rendered as a gauge that turns
amber/red as it's approached. This is the single biggest structural fix
in this plan: SPF allows exactly one record, so nothing about per-platform
SPF instructions can ever be shown in isolation without risking the
customer overwriting a previous platform's include — every SPF-touching
flow in this plan must go through this one component, never propose its
own record text directly.

**New card — `PlatformHealthMatrix.vue`** on `DomainDetailView.vue`: rows
= declared + detected platforms, columns = SPF / DKIM / Alignment,
colored status cells, click any cell → `PlatformSetupModal.vue` scoped to
that exact issue. Each row also gets a **"Remove"** action (with confirm)
for a platform the customer has decommissioned — removing it drops its
include from `SpfCompositionBuilder.vue`'s next computed record and stops
its DKIM monitoring nagging.

**Mimecast gets its own profile shape, not the generic ESP template.**
Every other platform in the v1 list signs and sends mail directly
(SendGrid, Mailchimp, etc.), so their profile is "here's our SPF include,
here's our DKIM CNAMEs." Mimecast is most commonly deployed as an
**outbound relay/gateway in front of the customer's own mail server** —
the original server may still do its own DKIM signing while Mimecast just
relays the message onward, or Mimecast may re-sign depending on
configuration. A profile that assumes "Mimecast signs your mail" would be
wrong for the most common real deployment. Mimecast's profile needs an
explicit branch: "Are you sending directly through Mimecast, or is
Mimecast relaying for your own mail server?" — each branch leading to
different SPF/DKIM guidance, surfaced as a sub-choice inside
`PlatformSetupModal.vue` specifically for this platform, not the uniform
flow every other tile gets.

**New small component — `DnsInfraPanel.vue`**: "Detected DNS
infrastructure — `ns1.x, ns2.x` → matched to {provider}" with a **"Not
right? Choose manually"** link opening `RegistrarOverrideModal.vue` (a
simple list of the curated registrars to pick by hand when auto-detect is
wrong or falls back to generic). Embedded inside both
`PlatformSetupModal.vue` and the existing `RecordReviewModal.vue`.

## Pain 2 — Concept Cards

**New component — `ConceptCardButton.vue`** (props: `conceptId`,
`contextData`): a small "?" icon. Click opens an anchored popover with the
concept's explanation, the user's own live values spliced in, an **"Ask a
follow-up"** button (opens the existing `AskFollowUp.vue` thread seeded
with this concept), and a **"Got it"** button that dismisses and calls a
new `POST /concepts/{id}/seen`. Placed next to: the compliance % figure
(`DmarcView.vue`), the alignment badges and header-from/envelope-from
labels (`DmarcAuthDrawer.vue` — labeled **"Envelope-From (Return-Path)"**,
not just "envelope-from," since admins in the original training calls used
"return-path" as the working term and the label needs to match what they'd
actually search for), the DMARC-stage badge
(`RoadmapTrack.vue`/`DomainDetailView.vue`), the MTA-STS mode label
(`MtaStsView.vue`).

**An umbrella "What is authentication?" card was missing from the first
draft of this spec** — every placement above explains one specific
mechanic (alignment, a stage, a mode), but none of them orient a true
beginner on the concept that ties them together. Add one
`ConceptCardButton.vue` instance at the top of `DmarcView.vue`'s verdict
banner area, scoped to `conceptId="dmarc.authentication_overview"`: "SPF
and DKIM are authentication mechanisms — they prove a message came from
where it claims. DMARC alignment then checks whether what authenticated
the message matches what your recipients actually see." This is the entry
point a customer reads *before* the granular cards make sense, not an
afterthought to them.

**New global entry point**: a persistent "?" icon in `AppTopbar.vue` next
to the alerts bell, opening **`GlossaryModal.vue`** — every concept card,
searchable, regardless of seen-state, for self-serve lookup anytime.

**New button — "Explain my setup"** on `DomainDetailView.vue`'s header,
opening **`DomainExplainerModal.vue`**: an auto-generated, personalized
writeup of this domain's actual posture in plain language (knowledge
layer + live data), with **"Send to client"** (reuses `email_service.py`,
an email input field) and **"Download as PDF"** (reuses
`pdf_report_service.py`'s rendering pattern) — this is the literal
replacement for the training call, handed to a non-technical stakeholder
instead of scheduled.

## Pain 3 — DKIM-fail sub-classification

No new modal — extends `DmarcAuthDrawer.vue`. When `verdict ==
"auth_failure"`, render a new **`DkimFailureDiagnosis.vue`** sub-section:
two ranked hypotheses (transit modification vs. key/selector mismatch)
each with their evidence bullets and a **"Fix this"** button. The
key-mismatch button opens `PlatformSetupModal.vue` (DKIM section,
pre-scrolled) when the source is a recognized platform; the
transit-modification button opens a small educational info panel (ARC,
forwarder limitations) with an **"Ask a follow-up"** entry point.

## Pain 4 — Per-source Readiness Scorecard

**New card — `EnforcementReadinessCard.vue`** on `RoadmapView.vue`,
directly under the existing `RoadmapTrack.vue`: one row per significant
source — status icon (✅ ready / ⚠️ blocking / ➖ below volume floor),
name, one-line blocking reason, a **"Fix this"** button
(→ `PlatformSetupModal.vue`), and a `ConceptCardButton.vue` explaining the
blocker. A progress pill at the top — **"{n} of {total} sources
ready"** — visually matching the existing `AppTopbar.vue` protection pill,
clicking it scrolls to the first blocker.

**Existing "Preview impact before advancing" button** (already built in
`RoadmapTrack.vue`) is upgraded to open as **`SimulationModal.vue`**
instead of an inline panel, rendering the same per-source checklist
layout as the scorecard above — requires a small backend extension to
`simulate-policy` so it returns every significant source's ready/blocking
status, not only the ones that would be affected.

## Pain 5 — MTA-STS hosting + per-MX scorecard

**New choice modal — `MtaStsHostingChoiceModal.vue`**, inserted at the
start of `WizardStep3Tls.vue`: **"Sentinel-hosted (recommended)"** vs.
**"Self-hosted (advanced)"**.
- Sentinel-hosted: shows exactly one CNAME record
  (`mta-sts.yourdomain.com → mta-sts-host.sentinel.app`) through the same
  `DnsInfraPanel.vue` + step-by-step + live-polling pattern, plus a live
  status strip — "Provisioning certificate… / ✅ Certificate ready / ✅
  Policy live and fetchable" — polled from a new
  `GET /domains/{id}/mta-sts/hosting-status`.
- Self-hosted: today's existing TXT-record-plus-manual-policy-file flow,
  unchanged.

**New card — `MxReadinessScorecard.vue`** on `MtaStsView.vue`: same visual
pattern as `EnforcementReadinessCard.vue`, one row per MX host — STARTTLS
status, cert status, blocking reason, **"Fix this"** button. Built
strictly from the existing STARTTLS-probe `SslCert` rows
(`host_type == "mx"`) — per the protocol-boundary note above, never from
a new HTTP-based check.

**The "Fix this" button must branch on the actual failure code, not assume
one universal remediation type** — the first draft of this spec said "cert
renewal guidance / registrar steps" as if those were interchangeable, but
they answer to completely different owners. An expired or misconfigured MX
certificate (`certificate-expired`, `certificate-host-mismatch`,
`certificate-not-trusted`) is almost always a **mail-server/hosting-
provider problem** — Exchange, Postfix, cPanel mail config — and the
registrar hand-holding pattern doesn't apply to it at all; that branch
opens a generic "renew/reissue your mail server's certificate" guidance
panel, not a DNS flow. Only the genuinely DNS-related codes
(`sts-policy-fetch-error`, `dnssec-invalid`, `tlsa-invalid`,
`no-policy-found`) route to `DnsInfraPanel.vue`'s registrar steps. This
branch reuses `_TLS_FIX_ACTIONS` (already built in `advisor_service.py`
for the TLS sender-recommendation pipeline) as the source of truth for
which failure codes get which treatment — not a new guess.

**New button — "Verify policy is publicly fetchable"** on
`MtaStsView.vue`: triggers a real server-side HTTPS GET against the
customer's actual `mta-sts.<domain>` and shows the raw pass/fail result —
distinct from the DNS-propagation check, this answers "would a real
sender actually succeed right now."

## Pain 6 — Subdomain Disposition Ledger

**Extends the existing "Discovered subdomains" card** on
`DomainDetailView.vue`: each undispositioned row gets three buttons
instead of today's single "Monitor this" — **[Monitor this]**
**[Exclude]** **[Covered by sp=]**.
- **Exclude** opens **`ExcludeSubdomainModal.vue`**, a required reason
  text field before confirming (stored, not silently dropped).
- **Covered by sp=** opens a small confirm modal explaining what `sp=`
  means (same `ConceptCardButton.vue` styling) before flagging it.

**New modal — `SubdomainDispositionModal.vue`**: surfaced from
`EnforcementReadinessCard.vue` when undispositioned mail-sending
subdomains are the blocker — a **"Resolve subdomains"** button opens this
modal, listing exactly the undispositioned ones with the same three-button
row UI. **Done** stays disabled until every row is resolved; closing it
refreshes the scorecard, which should now show unblocked.

## Portfolio rollup — missing from the first draft entirely

Every surface above was specified as single-domain only. Sentinel is
built MSP-first (the actual revenue driver, per the product's own
positioning) — an MSP managing 30 client domains needs to know "12 of 30
domains have an unresolved platform setup issue" without opening 30
domains one at a time. Designing every new feature in this plan as a
single-domain view and never rolling it up to the portfolio would
recreate exactly the kind of gap this whole plan exists to close, just one
layer up.

**New card — `PortfolioReadinessRollup.vue`** on `OverviewView.vue` (and
`MspView.vue` for an MSP's client list specifically): one row per blocker
category — "Platform setup incomplete," "Undispositioned subdomains,"
"MTA-STS hosting not verified," "Sources blocking enforcement" — each with
a count and the list of affected domains, click-through straight to that
domain's specific blocking surface (the exact modal/card relevant, not
just the domain's overview page). This turns the single-domain fixes above
into something an MSP can actually triage across a client list in one
view, rather than rediscovering each pain point domain-by-domain.

## New backend surfaces this requires (summary, not yet built)
- `app/knowledge/platforms/` — the platform-profile data (mirrors the
  existing `app/knowledge/dmarc.py` etc. pattern). Mimecast's profile
  carries a relay-vs-direct-send branch; every other v1 platform doesn't
  need one.
- A pure `compose_spf_record(declared_platforms, detected_platforms) ->
  str` function — the single source of truth `SpfCompositionBuilder.vue`
  renders, with the 10-lookup count computed alongside it. This is the
  one function every SPF-touching surface in this plan must call through;
  nothing proposes SPF text on its own.
- `sender_recommendations` gains a `declared` source (platform chosen in
  the wizard, or via the new retroactive "+ Add a sending platform" entry
  point, before any DMARC data exists) alongside today's
  detected-from-aggregate path.
- `concepts_seen` table (or a JSON column on `User`) for Concept Card
  dismissal tracking.
- `subdomain_dispositions` table + the new `recommendation_engine.py` HOLD
  rule described in Pain 6 above.
- MTA-STS managed hosting: ACME client integration, per-domain
  certificate storage, and the hosting/serving endpoint itself — the
  single largest net-new infrastructure piece in this entire plan, and
  the one most worth confirming direction on before starting (see open
  decisions above).
- `simulate-policy` extended to return all significant sources, not only
  affected ones.
- A portfolio-level rollup query (one pass across all of a tenant's
  domains, reusing each domain's already-computed readiness/disposition
  state rather than recomputing per-domain logic at the portfolio layer)
  feeding `PortfolioReadinessRollup.vue`.
