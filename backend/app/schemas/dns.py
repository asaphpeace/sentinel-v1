from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel


def _change_type(previous: str | None, current: str | None) -> str:
    if previous is None:
        return "added"
    if current is None:
        return "removed"
    return "modified"


def _is_security_alert(record_type: str, previous: str | None, current: str | None) -> bool:
    """Flag changes that represent a security regression or suspicious mutation."""
    if current is None:
        # Any critical record removed is notable
        return record_type in ("DMARC", "SPF", "MX")

    if record_type == "DMARC":
        # Policy downgrade
        prev_p = _extract_dmarc_policy(previous)
        curr_p = _extract_dmarc_policy(current)
        order = {"reject": 2, "quarantine": 1, "none": 0}
        if order.get(curr_p, -1) < order.get(prev_p, -1):
            return True

    if record_type == "SPF":
        # Permissive all introduced
        if current and ("+all" in current or " all" in current.lower()):
            return True

    return False


def _extract_dmarc_policy(value: str | None) -> str:
    if not value:
        return ""
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("p=") or part.lower().startswith("p ="):
            return part.split("=", 1)[1].strip()
    return ""


class DnsTimelineEntryOut(BaseModel):
    id: str
    domain_id: str
    domain_name: str | None
    record_type: str
    record_host: str
    previous_value: str | None
    current_value: str | None
    change_summary: str | None
    change_type: str          # added | modified | removed
    is_security_alert: bool
    detected_at: datetime
    risk_severity:    str | None = None   # info | warn | critical
    risk_explanation: str | None = None
    risk_action:      str | None = None
    risk_is_ai:       bool = False

    model_config = {"from_attributes": True}
