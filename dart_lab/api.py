import os
import hashlib
import json
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import APIKeyHeader
from pydantic import ValidationError

from .body_limit import BodyLimitMiddleware

from .adapters import normalize
from .detection import RULES
from .models import ApprovalRequest, Event, IngestRequest, ProposalRequest, LogBatch, LogRecord
from .store import Store
from .sources import SourceSettings
from .source_api import register_source_routes
from .push_gateway import PushGateway


def create_app(db_path=None, api_token=None, source_settings=None):
    token = api_token if api_token is not None else os.getenv("DART_API_TOKEN", "")
    path = db_path or os.getenv("DART_DB_PATH", "data/dart.db")

    settings = source_settings or SourceSettings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        if len(token) < 24:
            raise RuntimeError("DART_API_TOKEN must contain at least 24 characters")
        app.state.store = Store(path)
        gateway = None
        if settings.syslog_enabled and any(settings.networks.values()):
            gateway = PushGateway(settings, app.state.store)
            await gateway.start()
        try:
            yield
        finally:
            if gateway:
                await gateway.close()

    app = FastAPI(title="Threat Hunting Lab", version="0.3.0", lifespan=lifespan)
    app.add_middleware(BodyLimitMiddleware)
    header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def authenticate(key=Depends(header)):
        if not key or not secrets.compare_digest(key.encode(), token.encode()):
            raise HTTPException(401, "Invalid API key")

    protected = [Depends(authenticate)]
    register_source_routes(app, settings, token, authenticate)

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

    @app.post("/logs", dependencies=protected)
    def logs_ingest(batch: LogBatch):
        try:
            return app.state.store.ingest_logs(batch.records)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/logs", dependencies=protected)
    def logs(
        source: str = None,
        host: str = None,
        after: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
    ):
        return app.state.store.list_logs(source, host, after, limit)

    @app.post("/collect/{source}", dependencies=protected)
    async def collect(
        source: str,
        request: Request,
        format: str = "auto",
        host: str = None,
        vendor: str = None,
        product: str = None,
        asset_type: str = "other",
    ):
        """Agent-friendly JSON object/array, NDJSON, or newline-delimited text input."""
        try:
            raw = (await request.body()).decode("utf-8")
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            if content_type == "application/json":
                data = json.loads(raw)
                items = data if isinstance(data, list) else [data]
                if not all(isinstance(item, dict) for item in items):
                    raise ValueError("JSON input must contain objects")
                lines = [json.dumps(item, ensure_ascii=False) for item in items]
                format = "json"
            else:
                lines = [line for line in raw.splitlines() if line.strip()]
            key = request.headers.get("idempotency-key")
            records = [
                LogRecord(
                    source=source,
                    raw=line,
                    format=format,
                    host=host,
                    vendor=vendor,
                    product=product,
                    asset_type=asset_type,
                    record_id=hashlib.sha256(f"{key}:{i}".encode()).hexdigest() if key else None,
                )
                for i, line in enumerate(lines)
            ]
            if not 1 <= len(records) <= 5000:
                raise ValueError("expected 1-5000 records")
        except (ValueError, UnicodeError, ValidationError, RecursionError):
            raise HTTPException(
                422, "Expected 1-5000 valid records, <=64 KiB characters each, with valid metadata"
            )
        # SQLite work runs outside the ASGI event loop.
        from starlette.concurrency import run_in_threadpool

        try:
            return await run_in_threadpool(app.state.store.ingest_logs, records)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

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
