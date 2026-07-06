from pydantic import BaseModel


class EngagementCreate(BaseModel):
    tier: str  # cloud | exposure | credential | phishing | reachability | exploit
    domain_id: str | None = None
    scope: dict = {}


class EngagementOut(BaseModel):
    id: str
    tier: str
    domain_id: str | None
    scope: dict
    status: str
    approved_at: str | None
    expires_at: str | None
    created_at: str
