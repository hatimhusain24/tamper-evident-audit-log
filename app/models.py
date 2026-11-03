"""API schemas: the public contract, validated at the boundary."""

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.chain import ARCHIVE_EVENT, REDACTION_EVENT, canonical

MAX_PAYLOAD_BYTES = 32 * 1024
Ident = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
EventType = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,63}$")]


class EventIn(BaseModel):
    """Caller-supplied event. The timestamp is assigned by the server (see docs)."""
    model_config = ConfigDict(extra="forbid", json_schema_extra={"example": {
        "eventType": "RECORD_UPDATED", "actorId": "user-42", "resourceType": "CLIENT_ACCOUNT",
        "resourceId": "acc-1001", "payload": {"field": "email", "accountNumber": "9876543210"}}})

    eventType: EventType
    actorId: Ident
    resourceType: Ident
    resourceId: Ident
    payload: dict[str, Any] = {}

    @field_validator("eventType")
    @classmethod
    def not_reserved(cls, v: str) -> str:
        if v in (REDACTION_EVENT, ARCHIVE_EVENT):  # only the service may write these
            raise ValueError(f"{v} is a reserved system event type")
        return v

    @field_validator("payload")
    @classmethod
    def bounded(cls, v: dict) -> dict:
        if len(canonical(v)) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
        return v


class RedactionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fields: Annotated[list[Ident], Field(min_length=1, max_length=50)]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]
    requestedBy: Ident


class RetentionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    olderThanDays: Annotated[float | None, Field(ge=0)] = None  # default: AUDIT_RETENTION_DAYS
    requestedBy: Ident = "system:retention"


class EventOut(BaseModel):
    seq: int
    timestamp: str
    eventType: str
    actorId: str
    resourceType: str
    resourceId: str
    payload: dict[str, Any]
    fieldHashes: dict[str, str]
    prevHash: str
    hash: str


class EventPage(BaseModel):
    items: list[EventOut]
    nextCursor: int | None  # pass back as ?cursor= to fetch the next page; null = last page


class VerifyResult(BaseModel):
    valid: bool
    recordsChecked: int
    headSeq: int
    headHash: str  # anchor this value externally to detect truncation or full rewrites
    firstInvalidSeq: int | None
    violation: str | None
    detail: str | None


class RetentionResult(BaseModel):
    archivedCount: int
    throughSeq: int | None
    event: EventOut | None  # the chained RECORDS_ARCHIVED event that authorizes this run
