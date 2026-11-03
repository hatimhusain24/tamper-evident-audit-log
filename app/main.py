"""HTTP API. Run with:  uvicorn app.main:create_app --factory"""

import hmac
from datetime import datetime
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.chain import verify_chain
from app.compliance import access_report
from app.config import settings
from app.models import (
    EventIn,
    EventOut,
    EventPage,
    RedactionIn,
    RetentionIn,
    RetentionResult,
    VerifyResult,
)
from app.store import AuditStore, Conflict, NotFound


def create_app(db_path: str = settings.db_path, admin_key: str | None = settings.admin_key,
               retention_days: float = settings.retention_days) -> FastAPI:
    store = AuditStore(db_path)
    app = FastAPI(title="Tamper-Evident Audit Log", version="1.0.0",
                  description="Append-only, hash-chained audit events. No update/delete API.")

    def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> None:
        """High-impact operations (redaction, archival) need the admin key when one is set."""
        if admin_key and not hmac.compare_digest(x_admin_key or "", admin_key):
            raise HTTPException(401, "valid X-Admin-Key header required")

    @app.exception_handler(NotFound)
    def not_found(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(Conflict)
    def conflict(_: Request, exc: Conflict) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/audit/events", status_code=201, response_model=EventOut)
    def write_event(event: EventIn) -> dict:
        return store.append(event.model_dump())

    @app.get("/audit/events", response_model=EventPage)
    def query_events(
        actorId: str | None = None,
        resourceType: str | None = None,
        resourceId: str | None = None,
        eventType: str | None = None,
        start: Annotated[datetime | None, Query(alias="from")] = None,
        end: Annotated[datetime | None, Query(alias="to")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        cursor: Annotated[int, Query(ge=0)] = 0,
    ) -> dict:
        filters = {"actorId": actorId, "resourceType": resourceType,
                   "resourceId": resourceId, "eventType": eventType}
        items, next_cursor = store.query(filters, start, end, limit, cursor)
        return {"items": items, "nextCursor": next_cursor}

    @app.get("/audit/verify", response_model=VerifyResult)
    def verify() -> dict:
        return verify_chain(store.iter_chain())

    @app.post("/audit/events/{seq}/redactions", status_code=201, response_model=EventOut,
              dependencies=[Depends(require_admin)])
    def redact(seq: int, body: RedactionIn) -> dict:
        """Redact payload fields of one record. Returns the chained RECORD_REDACTED event."""
        return store.redact(seq, body.fields, body.reason, body.requestedBy)

    @app.get("/audit/export")
    def export(actorId: str | None = None, resourceId: str | None = None) -> dict:
        """Export all records for ONE actorId or resourceId as a verifiable bundle."""
        if (actorId is None) == (resourceId is None):
            raise HTTPException(422, "provide exactly one of actorId or resourceId")
        return store.export("actor_id", actorId) if actorId else \
            store.export("resource_id", resourceId)

    @app.get("/audit/reports/account-access", dependencies=[Depends(require_admin)])
    def account_access_report(
        requestedBy: Annotated[str, Query(min_length=1, max_length=128)],
        accountId: str | None = None,
        start: Annotated[datetime | None, Query(alias="from")] = None,
        end: Annotated[datetime | None, Query(alias="to")] = None,
    ) -> dict:
        """Scenario C: who accessed client account data, when and why, with integrity proof."""
        return access_report(store, accountId, start, end, requestedBy)

    @app.post("/audit/retention/run", response_model=RetentionResult,
              dependencies=[Depends(require_admin)])
    def run_retention(body: RetentionIn | None = None) -> dict:
        """Archive (tombstone) records older than the retention window."""
        body = body or RetentionIn()
        days = retention_days if body.olderThanDays is None else body.olderThanDays
        return store.archive(days, body.requestedBy)

    return app
