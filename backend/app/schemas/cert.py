from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel


class CertOut(BaseModel):
    id: str
    host: str
    host_type: str
    subject_cn: str | None
    issuer: str | None
    san: str | None
    not_after: datetime | None
    days_remaining: int | None
    tls_version: str | None
    starttls_supported: bool | None
    hostname_valid: bool | None
    status: str
    probe_error: str | None
    probed_at: datetime

    model_config = {"from_attributes": True}
