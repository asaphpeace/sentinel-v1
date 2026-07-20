import os as _os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    secret_key: str = "dev-secret-change-in-production"
    algorithm: str = "HS256"
    # Shortened from 480 (8h) — tokens are stateless JWTs with no server-side
    # revocation other than the token_version bump on password/2FA change, so
    # a leaked 8-hour token was a long exposure window. 60 minutes balances
    # that against not forcing re-logins constantly; the frontend should
    # silently re-authenticate or prompt for re-login on a 401, not crash.
    access_token_expire_minutes: int = 60

    imap_host: str = "mail.mailsentry.co.za"
    imap_port: int = 993
    imap_user: str = "reports@mailsentry.co.za"
    imap_password: str = ""

    reporting_domain: str = "mailsentry.co.za"
    # Managed MTA-STS hosting target (PAIN_POINT_RESOLUTION_PLAN.md Pain 5):
    # customers on hosting_mode="managed" publish ONE CNAME —
    # mta-sts.<their-domain> -> this hostname — and Sentinel serves the
    # policy dynamically based on the request's Host header. Was previously
    # misused as a URL *prefix* (a real RFC 8461 bug, now fixed); this is
    # the correct usage: a bare hostname for the CNAME target. The TLS
    # termination for arbitrary customer hostnames pointed here is an
    # infra-layer concern (e.g. Caddy/Traefik with on-demand TLS issuing a
    # cert per incoming SNI), not application code — see
    # app/routers/mta_sts_hosting.py's module docstring.
    mta_sts_hosting_cname_target: str = "mta-sts-host.mailsentry.co.za"
    app_base_url: str = "http://localhost:5173"

    # Comma-separated list of allowed frontend origins for CORS. Defaults
    # cover local dev only — production deployments must set this explicitly
    # via env (CORS_ORIGINS=https://app.example.com,https://app2.example.com).
    # Never default this to "*" with allow_credentials=True; that combination
    # is invalid per the CORS spec anyway (browsers reject it), but more
    # importantly it would mean any site can make authenticated requests
    # using a logged-in user's cookies/headers.
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    advisor_llm_url: str = "http://localhost:11434"
    advisor_llm_model: str = "sentinel:latest"
    advisor_enabled: bool = True
    advisor_provider: str = "ollama"          # "ollama" | "claude"
    anthropic_api_key: str = ""
    advisor_claude_model: str = "claude-haiku-4-5-20251001"

    imap_poll_interval: int = 300
    cert_probe_interval: int = 86400
    dns_poll_interval: int = 3600
    recommendation_interval: int = 86400
    # How often the job checks which tenants are due — not how often any one
    # tenant gets emailed. Due-ness itself is computed per-tenant from
    # last_report_sent_at against their weekly/monthly schedule, so checking
    # daily just means "send within a day of becoming due," not "send daily."
    scheduled_report_check_interval: int = 86400

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_publishable_key: str = ""

    # Stripe price IDs — create these in your Stripe dashboard
    stripe_price_starter_monthly: str = ""
    stripe_price_starter_annual: str = ""
    stripe_price_pro_monthly: str = ""
    stripe_price_pro_annual: str = ""
    stripe_price_msp_monthly: str = ""
    stripe_price_msp_annual: str = ""

    # Transactional email — sent via SMTP (aiosmtplib, STARTTLS on port 587).
    # If smtp_host is unset, send_email() logs the rendered email to stdout
    # instead of sending it, so dev/test environments work with zero config.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from_address: str = "noreply@mailsentry.co.za"
    email_from_name: str = "Sentinel"

    # Sentinel Command — Tier 0 cloud posture scanning. This is the AWS
    # account ID customers grant cross-account role access to; unset by
    # default (matches sendgrid_api_key/stripe keys' pattern) until this is
    # actually deployed with real scanning infrastructure — see
    # ARCHITECTURE.md's scanning-egress isolation note.
    command_aws_account_id: str = ""

    # boto3 clients that don't go through Prowler's own CLI (e.g. the
    # inspector2 client in cloud_scan_service.py) need an explicit region —
    # unlike sts, inspector2 has no global endpoint, and this environment
    # has no default region configured, which surfaces as a hard
    # NoRegionError rather than a silent wrong-region call. Inspector2 is
    # regional; a real deployment scanning multiple regions needs to either
    # iterate per-region or ask the customer which region(s) to scan — not
    # handled yet, single-region is today's simplification.
    command_aws_default_region: str = "us-east-1"

    # Prowler lives in its own venv (backend/.venv-prowler) — its exact pins
    # (pydantic==2.12.5, boto3==1.40.61 at time of writing) conflict outright
    # with this app's own. Cloudsplaining gets a SEPARATE isolated venv
    # (backend/.venv-iam-tools), not the same one as Prowler — installing
    # Cloudsplaining (which needs boto3>=1.41.0) alongside Prowler silently
    # upgrades Prowler's exact-pinned boto3 in the same venv, found by
    # actually testing it rather than assuming isolation was enough. PMapper
    # was dropped entirely: the latest published release (1.1.5) imports
    # `collections.Mapping`, removed in Python 3.10+, and patching an
    # installed third-party package's site-packages directly isn't something
    # to do — Cloudsplaining's own privilege-escalation detection (Rhino
    # Security Labs' methodology) covers the same need without it.
    # Paths are relative to the backend/ working directory the app runs
    # from; override via env for any other deployment layout.
    command_prowler_bin: str = (
        ".venv-prowler/Scripts/prowler.exe" if _os.name == "nt" else ".venv-prowler/bin/prowler"
    )
    command_iam_tools_python: str = (
        ".venv-iam-tools/Scripts/python.exe" if _os.name == "nt" else ".venv-iam-tools/bin/python"
    )
    command_scan_timeout_seconds: int = 900
    # How often the background job checks for connections due a rescan —
    # matches V1's existing interval-job settings (e.g. cert_probe_interval)
    # in spirit, not a per-connection schedule; every connection with an
    # active engagement gets rescanned every time this fires.
    command_rescan_interval: int = 21600  # 6h, matching BUILD_PLAN.md's original "recon every 6h" intent

    # How often the CloudTrail escalation poll runs (ITDR_DESIGN.md). Much
    # tighter than the posture rescan interval — this is meant to catch an
    # active attacker, not a slow drift in configuration, so it polls the
    # last 24h/since-last-poll window frequently rather than every 6h.
    command_threat_detection_interval: int = 300  # 5 minutes

    # Real e-signature for the Engagement rules-of-engagement gate
    # (ARCHITECTURE.md Section 9) — Dropbox Sign, not DocuSign, chosen there
    # for embedded-signing-first API + lower per-signature cost at this
    # volume. Blank by default (matches the stripe/sendgrid key pattern) —
    # request_signature() 503s cleanly with no key configured rather than
    # silently no-op'ing.
    dropbox_sign_api_key: str = ""
    # Dropbox Sign's sandbox mode: signatures complete instantly without a
    # real signer action and are NOT legally binding. True by default so a
    # fresh dev/test environment never accidentally sends a real, binding
    # signature request — must be explicitly set False for production.
    dropbox_sign_test_mode: bool = True

    # Escape hatch kept for local/CI testing of the Tier 0 scan pipeline
    # end-to-end without needing a real Dropbox Sign account — see
    # approve_engagement()'s docstring. Must be False in any real deployment;
    # the real gate is request_signature() + the signed-webhook callback.
    command_allow_direct_engagement_approval: bool = True

    # Phishing Tier A — Spoof Proof (PHISHING_DESIGN.md Section 2.3). DMARC
    # policy and domain registrations don't drift weekly, but a quarterly
    # check would catch a real change too slowly — monthly is the chosen
    # middle ground.
    command_impersonation_scan_interval_days: int = 30

    # Phishing Tier B — Human Simulation (PHISHING_DESIGN.md Section 3).
    # Tracking pixel/click/submit URLs are backend API endpoints, not
    # frontend routes — deliberately a separate setting from app_base_url
    # (which every existing link in this codebase points at the frontend),
    # not reused, since these are structurally different link targets.
    command_phishing_track_base_url: str = "http://localhost:9931"


settings = Settings()
