import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import APIKeyHeader

from .adapters import normalize
from .detection import RULES
from .models import ApprovalRequest, Event, IngestRequest, ProposalRequest
from .store import Store


def create_app(db_path=None, api_token=None):
    token = api_token if api_token is not None else os.getenv("DART_API_TOKEN", "")
    path = db_path or os.getenv("DART_DB_PATH", "data/dart.db")

    @asynccontextmanager
    async def lifespan(app):
        if len(token) < 24:
            raise RuntimeError("DART_API_TOKEN must contain at least 24 characters")
        app.state.store = Store(path)
        yield

    app = FastAPI(title="Threat Hunting Lab", version="0.1.0", lifespan=lifespan)
    header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def authenticate(key=Depends(header)):
        if not key or not secrets.compare_digest(key.encode(), token.encode()):
            raise HTTPException(401, "Invalid API key")

    protected = [Depends(authenticate)]

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "lab", "response_execution": False}

    @app.post("/events", dependencies=protected)
    def ingest(event: Event):
        return app.state.store.ingest(event)

    @app.post("/ingest", dependencies=protected)
    def ingest_native(request: IngestRequest):
        try:
            event = normalize(request.source, request.payload)
        except (KeyError, ValueError, TypeError, AttributeError):
            raise HTTPException(422, "Payload does not match the documented source format")
        return app.state.store.ingest(event)

    @app.get("/events", dependencies=protected)
    def events(limit: int = Query(100, ge=1, le=1000)):
        return app.state.store.list("events", limit)

    @app.get("/alerts", dependencies=protected)
    def alerts(limit: int = Query(100, ge=1, le=1000)):
        return app.state.store.list("alerts", limit)

    @app.get("/cases", dependencies=protected)
    def cases(limit: int = Query(100, ge=1, le=1000)):
        return app.state.store.list("cases", limit)

    @app.get("/cases/{case_id}", dependencies=protected)
    def case(case_id: str):
        result = app.state.store.get_case(case_id)
        if result is None:
            raise HTTPException(404, "Case not found")
        return result

    @app.get("/coverage", dependencies=protected)
    def coverage():
        return {
            "scope": "implemented demo rules, not measured detection effectiveness",
            "rules": RULES,
        }

    @app.get("/responses", dependencies=protected)
    def responses(limit: int = Query(100, ge=1, le=1000)):
        return app.state.store.list("proposals", limit)

    @app.post("/cases/{case_id}/responses", dependencies=protected)
    def propose(case_id: str, request: ProposalRequest):
        result = app.state.store.propose(case_id, request)
        if result is None:
            raise HTTPException(404, "Case not found")
        return result

    @app.post("/responses/{proposal_id}/approve", dependencies=protected)
    def approve(proposal_id: str, request: ApprovalRequest):
        try:
            result = app.state.store.approve(proposal_id, request)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        if result is None:
            raise HTTPException(404, "Proposal not found")
        return result

    return app


app = create_app()
