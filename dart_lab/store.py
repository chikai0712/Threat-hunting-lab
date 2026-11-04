import json
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .detection import detect
from .log_parser import parse_log, received_now
from .models import Event
from .source_normalizers import normalize_source


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS logs (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    source TEXT NOT NULL,
                    host TEXT,
                    body TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS logs_source ON logs(source, seq);
                CREATE INDEX IF NOT EXISTS logs_host ON logs(host, seq);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, event):
        with self.connect() as db:
            return self._ingest(db, event)

    def _ingest(self, db, event):
        inserted = db.execute(
            "INSERT OR IGNORE INTO events VALUES (?, ?)",
            (event.event_id, event.model_dump_json()),
        ).rowcount
        if not inserted:
            return {"event_id": event.event_id, "duplicate": True, "alerts": []}
        alerts = []
        for rule in detect(event):
            alert_id, case_id = str(uuid4()), str(uuid4())
            alert = {
                "id": alert_id,
                "event_id": event.event_id,
                "case_id": case_id,
                "rule": rule,
                "created_at": now(),
            }
            case = {
                "id": case_id,
                "title": rule["title"],
                "status": "open",
                "alert_id": alert_id,
                "event_id": event.event_id,
                "timeline": [
                    {
                        "at": event.timestamp.isoformat(),
                        "kind": "event",
                        "description": event.action,
                    }
                ],
                "created_at": now(),
            }
            db.execute("INSERT INTO alerts VALUES (?, ?)", (alert_id, json.dumps(alert)))
            db.execute("INSERT INTO cases VALUES (?, ?)", (case_id, json.dumps(case)))
            alerts.append(alert)
        return {"event_id": event.event_id, "duplicate": False, "alerts": alerts}

    def list(self, table, limit=100):
        # Table names are supplied exclusively by application code.
        assert table in {"events", "alerts", "cases", "proposals"}
        with self.connect() as db:
            return [
                json.loads(row[0])
                for row in db.execute(
                    f"SELECT body FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)
                )
            ]

    def get_case(self, case_id):
        with self.connect() as db:
            row = db.execute("SELECT body FROM cases WHERE id = ?", (case_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def propose(self, case_id, request):
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone():
                return None
            proposal = {
                "id": str(uuid4()),
                "case_id": case_id,
                **request.model_dump(),
                "status": "pending_approval",
                "created_at": now(),
                "execution_enabled": False,
            }
            db.execute(
                "INSERT INTO proposals VALUES (?, ?)", (proposal["id"], json.dumps(proposal))
            )
            return proposal

    def approve(self, proposal_id, request):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM proposals WHERE id = ?", (proposal_id,)).fetchone()
            if not row:
                return None
            proposal = json.loads(row[0])
            if proposal["status"] != "pending_approval":
                raise ValueError("proposal has already been reviewed")
            proposal.update(status="approved", approval={**request.model_dump(), "at": now()})
            db.execute(
                "UPDATE proposals SET body = ? WHERE id = ?", (json.dumps(proposal), proposal_id)
            )
            return proposal

    def ingest_logs(self, records):
        results = []
        with self.connect() as db:
            for record in records:
                identity = record.source + ":" + (record.record_id or str(uuid4()))
                log_id = hashlib.sha256(identity.encode()).hexdigest()
                fingerprint = hashlib.sha256(record.model_dump_json().encode()).hexdigest()
                previous = db.execute(
                    "SELECT fingerprint, body FROM logs WHERE id = ?", (log_id,)
                ).fetchone()
                if previous:
                    if previous[0] != fingerprint:
                        raise ValueError("record_id already exists with different contents")
                    results.append(
                        {
                            "log_id": log_id,
                            "duplicate": True,
                            "normalized": json.loads(previous[1]).get("normalized"),
                        }
                    )
                    continue
                parsed = parse_log(record.raw, record.format)
                received_at = received_now()
                normalized = normalize_source(record, parsed, received_at)
                host = normalized["host"]
                body = {
                    **record.model_dump(),
                    "id": log_id,
                    "received_at": received_at,
                    "host": host,
                    "parsed": parsed,
                    "normalized": normalized,
                }
                db.execute(
                    "INSERT INTO logs(id, fingerprint, source, host, body) VALUES (?, ?, ?, ?, ?)",
                    (log_id, fingerprint, record.source, host, json.dumps(body)),
                )
                event = Event(
                    event_id="log:" + log_id,
                    timestamp=normalized["timestamp"],
                    source=record.source,
                    host=host,
                    action=normalized["action"],
                    severity=normalized["severity"],
                    details={
                        "log_id": log_id,
                        "ingestion": "generic_log",
                        "parser_status": parsed["status"],
                        "normalized": normalized,
                        "fields": parsed["fields"],
                    },
                )
                self._ingest(db, event)
                results.append(
                    {
                        "log_id": log_id,
                        "duplicate": False,
                        "parser_status": parsed["status"],
                        "normalized": normalized,
                    }
                )
        return {"accepted": len(results), "records": results}

    def list_logs(self, source=None, host=None, after=0, limit=100):
        clauses, values = ["seq > ?"], [after]
        for column, value in (("source", source), ("host", host)):
            if value is not None:
                clauses.append(column + " = ?")
                values.append(value)
        values.append(limit + 1)
        with self.connect() as db:
            rows = db.execute(
                "SELECT seq, body FROM logs WHERE "
                + " AND ".join(clauses)
                + " ORDER BY seq LIMIT ?",
                values,
            ).fetchall()
        page = rows[:limit]
        return {
            "items": [{"cursor": seq, **json.loads(body)} for seq, body in page],
            "next_cursor": page[-1][0] if page else after,
            "has_more": len(rows) > limit,
        }
