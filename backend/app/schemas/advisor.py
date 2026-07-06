from pydantic import BaseModel


class AdvisorOut(BaseModel):
    message: str
    commend: bool
    citations: list[str] = []
    is_ai: bool = False
    model: str = ""
