from pydantic import BaseModel


class CloudConnectionCreate(BaseModel):
    provider: str  # aws | azure | gcp


class CloudConnectionSetupOut(BaseModel):
    id: str
    provider: str
    status: str
    external_id: str | None = None
    trust_policy: str | None = None
    cloudformation_template: str | None = None
    instructions: list[str] = []


class CloudConnectionOut(BaseModel):
    id: str
    provider: str
    status: str
    role_arn: str | None = None
    connected_at: str | None = None
    last_scanned_at: str | None = None
    created_at: str


class CloudConnectionVerifyRequest(BaseModel):
    role_arn: str
