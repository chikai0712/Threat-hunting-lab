import asyncio
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from dart_lab.api import create_app
from dart_lab.models import LogRecord
from dart_lab.push_gateway import PushGateway
from dart_lab.sources import SourceSettings
from dart_lab.store import Store

TOKEN = "source-test-token-not-for-production"


def configured(**values):
    return SourceSettings.from_env({"SYSLOG_ENABLED": "false", **values})


@pytest.mark.parametrize(
    "source,variable,payload,expected",
    [
        (
            "fortinet",
            "FORTINET_IPS",
            'date=2026-11-04 devname="fw1" action=deny srcip=192.0.2.1 dstip=198.51.100.1 srcport=12345 dstport=443 proto=6 logid=42',
            {"action": "deny", "source_ip": "192.0.2.1", "destination_port": 443, "host": "fw1"},
        ),
        (
            "cisco",
            "CISCO_IPS",
            "<166>Nov  4 12:00:00 switch1 %LINK-3-UPDOWN: test",
            {"action": "UPDOWN", "event_code": "%LINK-3-UPDOWN", "severity": "high"},
        ),
        (
            "windows",
            "WINDOWS_IPS",
            {
                "EventID": 4625,
                "ComputerName": "dc1",
                "EventData": {"TargetUserName": "alice", "IpAddress": "192.0.2.1"},
            },
            {"action": "logon", "outcome": "failure", "host": "dc1", "user": "alice"},
        ),
        (
            "linux",
            "LINUX_IPS",
            "<38>Nov  4 12:00:00 linux1 sshd: Failed password for invalid user test from 192.0.2.1 port 4321 ssh2",
            {"action": "logon", "outcome": "failure", "source_port": 4321},
        ),
        (
            "aws",
            "AWS_IPS",
            {
                "eventTime": "2026-11-04T12:00:00Z",
                "eventName": "StopLogging",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"arn": "arn:aws:iam::000000000000:user/lab"},
            },
            {"action": "StopLogging", "timestamp_basis": "event", "category": "cloud_audit"},
        ),
        (
            "kubernetes",
            "KUBERNETES_IPS",
            {
                "log": "started",
                "kubernetes": {
                    "namespace_name": "test",
                    "pod_name": "web-123",
                    "container_name": "web",
                },
            },
            {"action": "started", "namespace": "test", "pod": "web-123"},
        ),
        (
            "paloalto",
            "PALOALTO_IPS",
            "1,2026/11/04 12:00:00,serial,TRAFFIC,end,0,2026/11/04 12:00:00,192.0.2.1,198.51.100.1,0,0,rule,alice,,ssl,vsys,trust,untrust,eth1,eth2,profile,0,1,1,12345,443,0,0,0,tcp,deny",
            {"action": "deny", "source_ip": "192.0.2.1", "destination_port": 443, "user": "alice"},
        ),
    ],
)
def test_each_source_api_normalizes_without_token_for_allowed_peer(
    tmp_path, source, variable, payload, expected
):
    app = create_app(tmp_path / "test.db", TOKEN, configured(**{variable: "192.0.2.10"}))
    with TestClient(app, client=("192.0.2.10", 1234)) as client:
        args = (
            {"json": payload}
            if isinstance(payload, dict)
            else {"content": payload, "headers": {"Content-Type": "text/plain"}}
        )
        response = client.post(f"/api/v1/logs/{source}", **args)
        assert response.status_code == 200, response.text
        result = response.json()["records"][0]["normalized"]
        assert result["source"] == source
        assert result["schema_version"] == "1.0"
        for field, value in expected.items():
            assert result[field] == value
        # Source IP authorization grants push only; reading remains protected.
        assert client.get("/logs").status_code == 401
        stored = client.get("/logs", headers={"X-API-Key": TOKEN}).json()["items"][0]
        assert stored["peer"] == "192.0.2.10"
        assert stored["normalized"] == result
        assert stored["raw"]
        assert f"/api/v1/logs/{source}" in client.get("/openapi.json").json()["paths"]


def test_denied_disabled_and_forwarded_header_does_not_authorize(tmp_path):
    app = create_app(tmp_path / "test.db", TOKEN, configured(FORTINET_IPS="192.0.2.10"))
    with TestClient(app, client=("198.51.100.1", 1234)) as client:
        response = client.post(
            "/api/v1/logs/fortinet",
            content="test",
            headers={
                "X-Forwarded-For": "192.0.2.10",
                "X-Real-IP": "192.0.2.10",
                "X-API-Key": TOKEN,
            },
        )
        assert response.status_code == 403
        assert client.post("/api/v1/logs/cisco", content="test").status_code == 403
        assert client.get("/api/v1/sources").status_code == 401
        profiles = client.get("/api/v1/sources", headers={"X-API-Key": TOKEN}).json()["sources"]
        assert next(profile for profile in profiles if profile["source"] == "fortinet")["enabled"]


def test_optional_key_is_additional_to_ip_and_idempotency(tmp_path):
    settings = configured(FORTINET_IPS="192.0.2.10", SOURCE_PUSH_REQUIRE_TOKEN="true")
    app = create_app(tmp_path / "test.db", TOKEN, settings)
    with TestClient(app, client=("192.0.2.10", 1)) as client:
        assert client.post("/api/v1/logs/fortinet", content="hello").status_code == 401
        headers = {"X-API-Key": TOKEN, "Idempotency-Key": "batch1"}
        first = client.post("/api/v1/logs/fortinet", content="hello", headers=headers).json()
        second = client.post("/api/v1/logs/fortinet", content="hello", headers=headers).json()
        assert second["records"][0]["duplicate"]
        assert first["records"][0]["normalized"] == second["records"][0]["normalized"]
        assert (
            client.post("/api/v1/logs/fortinet", content="changed", headers=headers).status_code
            == 409
        )


def test_configuration_validation_and_ipv4_mapped_address():
    settings = SourceSettings.from_env(
        {"FORTINET_IPS": "192.0.2.10,192.0.2.11", "CISCO_IPS": "198.51.100.0/24"}
    )
    assert settings.source_for("::ffff:192.0.2.10") == "fortinet"
    assert settings.source_for("198.51.100.3") == "cisco"
    assert settings.source_for("203.0.113.1") is None
    with pytest.raises(ValueError, match="Ambiguous"):
        SourceSettings.from_env({"FORTINET_IPS": "192.0.2.0/24", "CISCO_IPS": "192.0.2.1"})
    with pytest.raises(ValueError, match="invalid IP"):
        SourceSettings.from_env({"FORTINET_IPS": "not-an-ip"})
    with pytest.raises(ValueError, match="must be true or false"):
        SourceSettings.from_env({"SYSLOG_ENABLED": "maybe"})
    # Shared NAT IP is supported by explicit HTTP source endpoints when auto Syslog is off.
    assert configured(FORTINET_IPS="192.0.2.1", CISCO_IPS="192.0.2.1").permits("cisco", "192.0.2.1")


def test_source_gateway_routes_by_peer_and_keeps_outbox_on_database_failure(tmp_path, monkeypatch):
    settings = SourceSettings.from_env({"FORTINET_IPS": "192.0.2.10", "CISCO_IPS": "192.0.2.11"})
    settings = replace(settings, spool=str(tmp_path / "spool.db"))
    store = Store(tmp_path / "logs.db")
    gateway = PushGateway(settings, store)
    assert gateway.enqueue(b"<189>action=deny devname=fw1", "192.0.2.10", "syslog_udp")
    assert gateway.enqueue(
        b"<166>Nov  4 12:00:00 switch %LINK-3-UPDOWN: test", "192.0.2.11", "syslog_tcp"
    )
    assert not gateway.enqueue(b"fake fortinet", "203.0.113.1", "syslog_udp")
    original = store.ingest_logs

    def unavailable(records):
        raise OSError("database unavailable")

    monkeypatch.setattr(store, "ingest_logs", unavailable)
    with pytest.raises(OSError):
        gateway.drain_once()
    assert len(gateway.outbox.batch()) == 2
    monkeypatch.setattr(store, "ingest_logs", original)
    restarted = PushGateway(settings, store)
    assert restarted.drain_once()
    assert not restarted.outbox.batch()
    items = store.list_logs()["items"]
    assert [item["source"] for item in items] == ["fortinet", "cisco"]
    assert [item["normalized"]["action"] for item in items] == ["deny", "UPDOWN"]
    asyncio.run(restarted.close())


def test_aws_wrapper_and_malformed_source_inputs(tmp_path):
    app = create_app(tmp_path / "test.db", TOKEN, configured(AWS_IPS="192.0.2.10"))
    with TestClient(app, client=("192.0.2.10", 1)) as client:
        response = client.post(
            "/api/v1/logs/aws", json={"Records": [{"eventName": "A"}, {"eventName": "B"}]}
        )
        assert response.json()["accepted"] == 2
        assert client.post("/api/v1/logs/aws", json=[1]).status_code == 422
        assert client.post("/api/v1/logs/aws", content="").status_code == 422
        assert (
            client.post("/api/v1/logs/aws", content="x" * (2 * 1024 * 1024 + 1)).status_code == 413
        )


def test_normalization_preserves_unrecognized_data_and_safe_optional_values(tmp_path):
    store = Store(tmp_path / "logs.db")
    result = store.ingest_logs(
        [LogRecord(source="fortinet", raw="action=deny srcip=invalid dstport=999999 eventtime=bad")]
    )
    normalized = result["records"][0]["normalized"]
    assert normalized["source_ip"] is None
    assert normalized["destination_port"] is None
    assert normalized["timestamp_basis"] == "received"
    assert store.list_logs()["items"][0]["raw"].endswith("eventtime=bad")
