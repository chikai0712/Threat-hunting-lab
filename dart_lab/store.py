import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .detection import detect


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
