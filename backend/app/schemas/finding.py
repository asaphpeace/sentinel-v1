from pydantic import BaseModel


class FindingOut(BaseModel):
    id: str
    engagement_id: str
    asset_id: str | None
    tier: str
    severity: str
    title: str
    status: str
    check_id: str | None
    detail: str | None
    remediation_guidance: str | None
    discovered_at: str


class CloudPrivEscPathOut(BaseModel):
    id: str
    engagement_id: str
    source_principal_arn: str
    target_principal_arn: str
    technique_chain: list[str]
    severity: str
    discovered_at: str
