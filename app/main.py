"""HTTP API. Run with:  uvicorn app.main:create_app --factory"""

from datetime import datetime
from typing import Annotated

from fastapi import FastAPI, Query

from app.chain import verify_chain
from app.config import settings
from app.models import EventIn, EventOut, EventPage, VerifyResult
from app.store import AuditStore


def create_app(db_path: str = settings.db_path) -> FastAPI:
    store = AuditStore(db_path)
    app = FastAPI(title="Tamper-Evident Audit Log", version="1.0.0",
                  description="Append-only, hash-chained audit events. No update/delete API.")

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

    return app
