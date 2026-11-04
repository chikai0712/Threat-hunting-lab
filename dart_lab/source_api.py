"""One documented normalization/push endpoint for each supported source profile."""

import hashlib
import json
import secrets

from fastapi import Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .models import LogRecord
from .sources import PROFILES


def decode_records(raw, content_type, source):
    if content_type == "application/json":
        data = json.loads(raw)
        if source == "aws" and isinstance(data, dict) and "Records" in data:
            data = data["Records"]
        data = data if isinstance(data, list) else [data]
        if not all(isinstance(item, dict) for item in data):
            raise ValueError("JSON logs must be objects")
        return [(json.dumps(item, ensure_ascii=False), "json") for item in data]
    return [(line, "auto") for line in raw.splitlines() if line.strip()]


def register_source_routes(app, settings, token, authenticate):
    @app.get("/api/v1/sources", dependencies=[Depends(authenticate)], tags=["Source configuration"])
    def sources():
        return {
            "sources": settings.describe(),
            "syslog_enabled": settings.syslog_enabled,
            "syslog_port": settings.syslog_port,
            "push_requires_token": settings.require_token,
        }

    def make_endpoint(source):
        async def push(request: Request):
            if not settings.networks[source]:
                raise HTTPException(
                    403, "Source is disabled; configure its IP environment variable"
                )
            peer = request.client.host if request.client else ""
            if not settings.permits(source, peer):
                raise HTTPException(403, f"Peer IP {peer} is not permitted for {source}")
            if settings.require_token:
                key = request.headers.get("x-api-key", "")
                if not key or not secrets.compare_digest(key.encode(), token.encode()):
                    raise HTTPException(401, "Invalid API key")
            try:
                payloads = decode_records(
                    (await request.body()).decode("utf-8"),
                    request.headers.get("content-type", "").split(";")[0].strip(),
                    source,
                )
                if not 1 <= len(payloads) <= 5000:
                    raise ValueError("expected 1-5000 records")
                key = request.headers.get("idempotency-key")
                _, vendor, product, asset = PROFILES[source]
                records = [
                    LogRecord(
                        source=source,
                        raw=raw,
                        format=format,
                        peer=peer,
                        vendor=vendor,
                        product=product,
                        asset_type=asset,
                        record_id=hashlib.sha256(f"{peer}:{key}:{i}".encode()).hexdigest()
                        if key
                        else None,
                    )
                    for i, (raw, format) in enumerate(payloads)
                ]
            except (ValueError, UnicodeError, RecursionError):
                raise HTTPException(
                    422,
                    "Expected 1-5000 JSON objects or text lines; each raw log <=65536 characters",
                )
            try:
                return await run_in_threadpool(app.state.store.ingest_logs, records)
            except ValueError as exc:
                raise HTTPException(409, str(exc))

        return push

    for source, (variable, _, _, _) in PROFILES.items():
        app.add_api_route(
            f"/api/v1/logs/{source}",
            make_endpoint(source),
            methods=["POST"],
            name=f"push_{source}",
            tags=["Source normalization APIs"],
            summary=f"Normalize and store {source} logs",
            description=f"Enabled by {variable}. Accepts configured socket peer IPs only. JSON object/array, NDJSON or newline-delimited text. Returns normalized records.",
            openapi_extra={
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    {"type": "object"},
                                    {"type": "array", "items": {"type": "object"}},
                                ]
                            }
                        },
                        "text/plain": {"schema": {"type": "string"}},
                        "application/x-ndjson": {"schema": {"type": "string"}},
                    },
                }
            },
        )
