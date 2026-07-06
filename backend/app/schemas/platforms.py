from __future__ import annotations
from pydantic import BaseModel


class PlatformSummaryOut(BaseModel):
    """One tile in the platform picker (wizard step or retroactive add)."""
    key: str
    name: str
    category: str
    requires_branch_choice: bool = False   # true only for Mimecast


class PlatformStatusOut(BaseModel):
    """One row in the Platform Health Matrix."""
    key: str
    name: str
    declared: bool
    detected: bool
    spf_status: str        # included | missing
    dkim_status: str       # configured | not_configured | unknown
    alignment_status: str  # aligned | unaligned | unknown


class SpfCompositionOut(BaseModel):
    record: str
    mechanisms: list[str]
    total_lookups: int
    lookup_limit: int
    over_limit: bool
    near_limit: bool
    warnings: list[str]
    # Whether a live SPF record was actually fetched for this domain before
    # merging — false means starting fresh, no existing record found.
    existing_record_found: bool = False
    # True once the lookup count reflects a real recursive DNS resolution
    # (compose_spf_record_live), not the static per-mechanism estimate.
    real_lookup_count: bool = False


class PlatformSetupCardOut(BaseModel):
    """Everything PlatformSetupModal.vue needs for one platform."""
    key: str
    name: str
    category: str
    dkim_kind: str | None
    dkim_description: str | None
    dkim_selector_pattern: str | None
    # The publish step for DKIM, distinct from dkim_description (which only
    # explains how to get the value FROM the platform) — dkim_record_type is
    # "TXT" or "CNAME" per profile, dkim_host_pattern is the generic host
    # shape (selector is account-specific, filled in from the platform's
    # own dashboard, never known to Sentinel in advance).
    dkim_record_type: str | None = None
    dkim_host_pattern: str | None = None
    admin_path: list[str]
    gotchas: list[str]
    return_path_note: str | None
    spf_composition: SpfCompositionOut
    # Registrar hand-holding, reused verbatim from registrar_service.py
    registrar_key: str
    registrar_name: str
    registrar_steps: list[str]
    registrar_steps_dkim: list[str] = []
    registrar_help_url: str | None
    nameservers: list[str]
    record_host: str
    record_type: str = "TXT"
