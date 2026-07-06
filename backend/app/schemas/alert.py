from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel


class AlertOut(BaseModel):
    id: str
    domain_id: str | None
    severity: str
    category: str
    title: str
    body: str
    action: str | None = None
    narration: str | None
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}
