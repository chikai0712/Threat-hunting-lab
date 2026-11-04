"""Replay synthetic sensor events against the running local API."""

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

base = os.getenv("DART_API_URL", "http://127.0.0.1:8000").rstrip("/")
token = os.environ["DART_API_TOKEN"]


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = Request(
        base + path, data=data, headers={"X-API-Key": token, "Content-Type": "application/json"}
    )
    with urlopen(req, timeout=10) as response:
        return json.load(response)


for path in sorted((Path(__file__).resolve().parents[1] / "samples").glob("*.json")):
    result = call("/ingest", json.loads(path.read_text()))
    print(path.name, json.dumps(result, ensure_ascii=False))
print("Cases:", len(call("/cases")))
print("Coverage:", json.dumps(call("/coverage"), ensure_ascii=False))
