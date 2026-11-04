import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dart_lab.adapters import normalize
from dart_lab.api import create_app
from dart_lab.store import Store

TOKEN = "test-token-only-not-a-secret-123456"
SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "test.db", TOKEN)) as test_client:
        test_client.headers["X-API-Key"] = TOKEN
        yield test_client


@pytest.mark.parametrize(
    "name,technique",
    [
        ("endpoint", "T1110"),
        ("network", None),
        ("aws", "T1562.008"),
        ("container", "T1059.004"),
    ],
)
def test_sensor_to_case_and_replay(client, name, technique):
    sample = json.loads((SAMPLES / f"{name}.json").read_text())
    response = client.post("/ingest", json=sample)
    assert response.status_code == 200
    alert = response.json()["alerts"][0]
    assert alert["rule"]["technique"] == technique
    case = client.get("/cases/" + alert["case_id"]).json()
    assert case["event_id"] == response.json()["event_id"]
    assert len(case["timeline"]) == 1
    assert client.post("/ingest", json=sample).json()["duplicate"] is True
    assert len(client.get("/cases").json()) == 1


def test_authentication(client):
    client.headers.pop("X-API-Key")
    assert client.get("/health").status_code == 200
    assert client.get("/cases").status_code == 401
    assert client.post("/ingest", json={"source": "wazuh", "payload": {}}).status_code == 401
    assert (
        client.post("/responses/x/approve", json={"reviewer": "a", "note": "b"}).status_code == 401
    )
    client.headers["X-API-Key"] = "wrong"
    assert client.get("/alerts").status_code == 401


def test_invalid_input(client):
    for payload in ({}, {"rule": None}, {"rule": {"level": "bad"}}):
        assert (
            client.post("/ingest", json={"source": "wazuh", "payload": payload}).status_code == 422
        )
    assert client.get("/cases?limit=1001").status_code == 422
    assert (
        client.post(
            "/events",
            json={
                "event_id": "invalid",
                "timestamp": "2026-11-04T01:00:00",
                "source": "wazuh",
                "action": "normal",
            },
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"eventName": "GetTrailStatus"},
        {"errorCode": "AccessDenied"},
    ],
)
def test_cloudtrail_non_detection(client, changes):
    sample = json.loads((SAMPLES / "aws.json").read_text())
    sample["payload"].update(changes)
    assert client.post("/ingest", json=sample).json()["alerts"] == []
    assert client.get("/cases").json() == []


def test_response_requires_case_and_review_does_not_execute(client):
    sample = json.loads((SAMPLES / "aws.json").read_text())
    case_id = client.post("/ingest", json=sample).json()["alerts"][0]["case_id"]
    body = {"action": "collect_evidence", "target": "lab-host", "rationale": "investigate"}
    assert client.post("/cases/missing/responses", json=body).status_code == 404
    proposal = client.post(f"/cases/{case_id}/responses", json=body).json()
    assert proposal["status"] == "pending_approval"
    path = f"/responses/{proposal['id']}/approve"
    approved = client.post(path, json={"reviewer": "lab-user", "note": "reviewed"}).json()
    assert approved["status"] == "approved"
    assert approved["execution_enabled"] is False
    assert approved["approval"]["reviewer"] == "lab-user"
    assert client.post(path, json={"reviewer": "other", "note": "again"}).status_code == 409
    assert client.post(f"/responses/{proposal['id']}/execute").status_code == 404


def test_persistence_and_concurrent_dedup(tmp_path):
    path = tmp_path / "persist.db"
    store = Store(path)
    sample = json.loads((SAMPLES / "aws.json").read_text())
    event = normalize(**sample)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: store.ingest(event), range(8)))
    assert sum(not result["duplicate"] for result in results) == 1
    reloaded = Store(path)
    assert len(reloaded.list("events")) == len(reloaded.list("cases")) == 1


def test_missing_token_fails_startup(tmp_path):
    with pytest.raises(RuntimeError, match="DART_API_TOKEN"):
        with TestClient(create_app(tmp_path / "test.db", "")):
            pass
