import asyncio
import base64
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dart_lab.api import create_app
from dart_lab.collector import (
    Outbox,
    collect_cloudwatch,
    collect_file_once,
    read_frame,
    record_bytes,
)
from dart_lab.log_parser import parse_log
from dart_lab.models import LogRecord

TOKEN = "log-test-token-not-for-production"


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "test.db", TOKEN)) as client:
        client.headers["X-API-Key"] = TOKEN
        yield client


def options(**kwargs):
    values = dict(
        source="test-device",
        encoding="utf-8",
        format="auto",
        vendor=None,
        product=None,
        host=None,
        asset_type="other",
        region="us-east-1",
        overlap_seconds=300,
        lookback_minutes=60,
    )
    values.update(kwargs)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    "raw,parser",
    [
        (
            '<134>1 2026-11-04T12:00:00+08:00 fw.example app 12 ID47 [x note="a\\]b"][y] allowed',
            "syslog_rfc5424",
        ),
        ("<166>Nov  4 12:00:00 switch-01 %LINK-3-UPDOWN: interface changed", "syslog_rfc3164"),
        ("CEF:0|Vendor|Firewall|1|100|blocked|8|src=192.0.2.1 msg=blocked access", "cef"),
        ('date=2026-11-04 devname="fw-01" action=deny msg="blocked traffic"', "kv"),
        ('{"message":"service started","timestamp":"2026-11-04T12:00:00Z"}', "json"),
        ("unrecognized application log", "text"),
    ],
)
def test_common_formats(raw, parser):
    result = parse_log(raw)
    assert result["parser"] == parser
    assert result["status"] in ("parsed", "unparsed")


def test_cef_escaping_and_syslog_envelope():
    raw = r"<134>1 2026-11-04T12:00:00Z fw app - - - CEF:0|Ven\|dor|FW|1|42|bad\|login|9|msg=some text cs1=a\=b src=192.0.2.1"
    parsed = parse_log(raw)
    assert parsed["vendor"] == "Ven|dor"
    assert parsed["message"] == "bad|login"
    assert parsed["severity"] == "critical"
    assert parsed["fields"]["payload"]["msg"] == "some text"
    assert parsed["fields"]["payload"]["cs1"] == "a=b"
    assert parsed["timestamp"] == "2026-11-04T12:00:00+00:00"


def test_legacy_time_is_not_guessed():
    parsed = parse_log("<134>Dec 31 23:59:59 router test")
    assert "timestamp" not in parsed
    assert "receipt time" in parsed["fields"]["timestamp_note"]


@pytest.mark.parametrize(
    "raw,format",
    [
        ("{broken", "json"),
        ("<999>bad", "syslog"),
        ("CEF:0|bad", "cef"),
        ("<134>1 2026-11-04T12:00:00Z fw app - - [unclosed", "syslog"),
    ],
)
def test_parse_errors_keep_raw_in_storage(client, raw, format):
    result = client.post(
        "/logs", json={"records": [{"source": "unknown", "raw": raw, "format": format}]}
    )
    assert result.status_code == 200
    item = client.get("/logs").json()["items"][0]
    assert item["raw"] == raw
    assert item["parsed"]["status"] == "error"
    assert len(client.get("/events").json()) == 1


def test_repeated_records_distinct_without_id_and_dedup_with_id(client):
    record = {"source": "firewall", "raw": "same event"}
    for _ in range(2):
        assert client.post("/logs", json={"records": [record]}).status_code == 200
    record["record_id"] = "stable-id"
    first = client.post("/logs", json={"records": [record]}).json()
    repeated = client.post("/logs", json={"records": [record]}).json()
    assert not first["records"][0]["duplicate"]
    assert repeated["records"][0]["duplicate"]
    assert len(client.get("/logs").json()["items"]) == 3


def test_conflicting_id_rolls_back_entire_batch(client):
    record = {"source": "fw", "raw": "original", "record_id": "1"}
    client.post("/logs", json={"records": [record]})
    response = client.post(
        "/logs",
        json={
            "records": [
                {"source": "fw", "raw": "new", "record_id": "2"},
                {**record, "raw": "changed"},
            ]
        },
    )
    assert response.status_code == 409
    assert len(client.get("/logs").json()["items"]) == 1
    assert len(client.get("/events").json()) == 1


def test_cursor_filter_and_unknown_source_do_not_create_cases(client):
    client.post(
        "/logs",
        json={
            "records": [
                {"source": "firewall", "raw": f"record {i}", "host": "fw1"} for i in range(3)
            ]
            + [{"source": "router", "raw": "another"}]
        },
    )
    first = client.get("/logs?source=firewall&host=fw1&limit=2").json()
    assert len(first["items"]) == 2 and first["has_more"]
    last = client.get(f"/logs?source=firewall&after={first['next_cursor']}&limit=2").json()
    assert len(last["items"]) == 1 and not last["has_more"]
    assert client.get("/cases").json() == []


@pytest.mark.parametrize(
    "body,content_type,count",
    [
        ('{"message":"ok"}', "application/json", 1),
        ('[{"message":"a"},{"message":"b"}]', "application/json", 2),
        ('{"message":"a"}\n{"message":"b"}\n', "application/x-ndjson", 2),
        ("line one\nline two\n", "text/plain", 2),
    ],
)
def test_agent_friendly_http(client, body, content_type, count):
    headers = {"Content-Type": content_type, "Idempotency-Key": "batch-1"}
    assert (
        client.post("/collect/windows-ad", content=body, headers=headers).json()["accepted"]
        == count
    )
    replay = client.post("/collect/windows-ad", content=body, headers=headers).json()
    assert all(record["duplicate"] for record in replay["records"])
    assert len(client.get("/logs").json()["items"]) == count


def test_http_validation_and_auth(client):
    assert (
        client.post(
            "/collect/linux", content=b"", headers={"Content-Type": "text/plain"}
        ).status_code
        == 422
    )
    assert client.post("/collect/linux", json=[1]).status_code == 422
    assert client.post("/logs", json={"records": []}).status_code == 422
    assert client.post("/collect/linux", content=b"x" * (2 * 1024 * 1024 + 1)).status_code == 413
    client.headers.pop("X-API-Key")
    assert client.post("/collect/linux", json={"message": "x"}).status_code == 401
    assert client.get("/logs").status_code == 401


def test_tcp_framing_fragmentation_multiple_frames_and_limits():
    async def scenario():
        reader = asyncio.StreamReader(limit=65537)
        frames = [b"<134>hello", "UTF8 中文".encode(), b"line"]
        wire = str(len(frames[0])).encode() + b" " + frames[0]
        wire += str(len(frames[1])).encode() + b" " + frames[1] + frames[2] + b"\n"

        async def feed():
            for byte in wire:
                reader.feed_data(bytes([byte]))
                await asyncio.sleep(0)
            reader.feed_eof()

        producer = asyncio.create_task(feed())
        for expected in frames:
            assert await read_frame(reader) == expected
        assert await read_frame(reader) is None
        await producer
        for invalid in (b"65537 x", b"999999999 x", b"0 ", b"unterminated"):
            stream = asyncio.StreamReader()
            stream.feed_data(invalid)
            stream.feed_eof()
            with pytest.raises(ValueError):
                await read_frame(stream)

    asyncio.run(scenario())


def test_non_utf8_bytes_are_preserved():
    data = b"legacy \xff message"
    record = record_bytes(data, options(), "syslog_udp", "192.0.2.1")
    assert base64.b64decode(record.raw_base64) == data
    assert "\ufffd" in record.raw


def test_file_checkpoint_partial_line_and_rotation(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(b"first\npartial")
    outbox = Outbox(tmp_path / "outbox.db")
    assert collect_file_once(path, outbox, options(), follow=True) == 1
    assert collect_file_once(path, outbox, options(), follow=True) == 0
    with path.open("ab") as stream:
        stream.write(b" second\n")
    assert collect_file_once(path, outbox, options(), follow=True) == 1
    path.rename(tmp_path / "app.log.1")
    path.write_bytes(b"rotated\n")
    assert collect_file_once(path, outbox, options(), follow=True) == 1
    assert [item[1]["raw"] for item in outbox.batch()] == ["first", "partial second", "rotated"]
    restarted = Outbox(tmp_path / "outbox.db")
    assert collect_file_once(path, restarted, options(), follow=True) == 0


def test_outbox_retains_failure_and_replays_after_restart(tmp_path, monkeypatch):
    import dart_lab.collector as module

    path = tmp_path / "outbox.db"
    outbox = Outbox(path)
    outbox.append([LogRecord(source="router", raw="event")])
    original = outbox.batch()

    def offline(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(module, "urlopen", offline)
    with pytest.raises(OSError):
        outbox.deliver("http://example.invalid", TOKEN)
    assert Outbox(path).batch() == original

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"accepted":1}'

    monkeypatch.setattr(module, "urlopen", lambda *a, **k: Response())
    assert outbox.deliver("http://example.invalid", TOKEN) == 1
    assert outbox.batch() == []


def test_cloudwatch_pagination_cursor_and_stable_event_ids(tmp_path):
    outbox = Outbox(tmp_path / "aws.db")
    calls = []

    class Client:
        def filter_log_events(self, **kwargs):
            calls.append(kwargs)
            if "nextToken" not in kwargs:
                return {
                    "events": [{"eventId": "a", "message": "AWS test", "logStreamName": "stream"}],
                    "nextToken": "next",
                }
            return {"events": []}

    assert collect_cloudwatch(Client(), ["/lab/test"], outbox, options()) == 1
    before = outbox.batch()
    assert collect_cloudwatch(Client(), ["/lab/test"], outbox, options()) == 1
    assert outbox.batch() == before
    assert len(calls) == 4
    assert calls[1]["nextToken"] == "next"
    assert outbox.checkpoint("cloudwatch:test-device:us-east-1:/lab/test") is not None


def test_fortinet_priority_prefixed_kv_and_windows_host():
    parsed = parse_log('<189>date=2026-11-04 devname="forti-lab" action=deny msg="blocked"')
    assert parsed["status"] == "parsed"
    assert parsed["host"] == "forti-lab"
    assert parsed["fields"]["payload"]["action"] == "deny"
    parsed = parse_log('{"ComputerName":"ad-01","level":"warning","EventID":4625}')
    assert parsed["host"] == "ad-01"
    assert parsed["severity"] == "medium"


def test_chunked_request_limit():
    from dart_lab.body_limit import BodyLimitMiddleware

    async def scenario():
        called, sent = [], []

        async def app(scope, receive, send):
            called.append(True)

        chunks = iter(
            [
                {"type": "http.request", "body": b"ab", "more_body": True},
                {"type": "http.request", "body": b"cd", "more_body": False},
            ]
        )

        async def receive():
            return next(chunks)

        async def send(message):
            sent.append(message)

        await BodyLimitMiddleware(app, max_bytes=3)(
            {"type": "http", "method": "POST"}, receive, send
        )
        assert not called
        assert sent[0]["status"] == 413

    asyncio.run(scenario())
