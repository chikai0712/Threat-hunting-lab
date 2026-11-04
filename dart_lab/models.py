from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    source: Literal["wazuh", "suricata", "falco", "cloudtrail"]
    host: Optional[str] = None
    actor: Optional[str] = None
    action: str = Field(min_length=1)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value


class IngestRequest(BaseModel):
    source: Literal["wazuh", "suricata", "falco", "cloudtrail"]
    payload: Dict[str, Any]


class ProposalRequest(BaseModel):
    action: Literal["isolate_host", "disable_account", "block_ip", "collect_evidence"]
    target: str = Field(min_length=1, max_length=256)
    rationale: str = Field(min_length=1, max_length=2000)


class ApprovalRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=2000)
