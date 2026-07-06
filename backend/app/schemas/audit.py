from __future__ import annotations
from pydantic import BaseModel
from datetime import datetime


class AuditLogEntryOut(BaseModel):
    id: str
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: str | None
    target_label: str | None
    before: dict | None
    after: dict | None
    ip_address: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
