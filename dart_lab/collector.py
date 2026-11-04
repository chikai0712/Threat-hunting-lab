"""Syslog/file/CloudWatch collection with a durable SQLite HTTP outbox."""

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import signal
import sqlite3
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from .models import LogRecord
from .tls_receiver import TLSReceiver

LOG = logging.getLogger("threat-log-collector")
MAX_FRAME = 65536


class Outbox:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS checkpoints (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def append(self, records, checkpoint=None):
        with self.connect() as db:
            for record in records:
                # Do not mutate caller-owned records; stable IDs survive forwarding retries.
                record = record.model_copy(update={"record_id": record.record_id or str(uuid4())})
                identity = record.source + ":" + record.record_id
                db.execute(
                    "INSERT OR IGNORE INTO pending VALUES (?, ?)",
                    (identity, record.model_dump_json()),
                )
            if checkpoint:
                key, value = checkpoint
                db.execute(
                    "INSERT OR REPLACE INTO checkpoints VALUES (?, ?)", (key, json.dumps(value))
                )

    def checkpoint(self, key):
        with self.connect() as db:
            row = db.execute("SELECT body FROM checkpoints WHERE id = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def batch(self):
        with self.connect() as db:
            rows = db.execute("SELECT id, body FROM pending ORDER BY rowid LIMIT 100").fetchall()
        selected, size = [], 0
        for identity, body in rows:
            size += len(body.encode()) + 2
            if size > 1024 * 1024:
                break
            selected.append((identity, json.loads(body)))
        return selected

    def acknowledge(self, ids):
        with self.connect() as db:
            db.executemany("DELETE FROM pending WHERE id = ?", [(identity,) for identity in ids])

    def deliver(self, url, token):
        batch = self.batch()
        if not batch:
            return 0
        body = json.dumps({"records": [record for _, record in batch]}, ensure_ascii=False).encode()
        request = Request(
            url.rstrip("/") + "/logs",
            data=body,
            headers={"X-API-Key": token, "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=15) as response:
            result = json.load(response)
        if result.get("accepted") != len(batch):
            raise RuntimeError("API did not acknowledge the full batch")
        self.acknowledge([identity for identity, _ in batch])
        return len(batch)


def record_bytes(data, options, transport, peer=None):
    if not data or len(data) > MAX_FRAME:
        raise ValueError("frame must be 1-65536 bytes")
    return LogRecord(
        source=options.source,
        raw=data.decode(options.encoding, errors="replace"),
        raw_base64=base64.b64encode(data).decode(),
        format=options.format,
        vendor=options.vendor,
        product=options.product,
        asset_type=options.asset_type,
        host=options.host,
        transport=transport,
        peer=peer,
    )


def allowed(peer, networks):
    address = ipaddress.ip_address(peer)
    return any(address in network for network in networks)


async def read_frame(reader):
    """RFC6587 octet-counted or LF-delimited framing. Returns None on clean EOF."""
    first = await reader.read(1)
    if not first:
        return None
    prefix = first
    if first.isdigit():
        while prefix[-1:].isdigit():
            if len(prefix) > 5:
                raise ValueError("invalid octet-counted frame length")
            next_byte = await reader.readexactly(1)
            prefix += next_byte
        if prefix.endswith(b" "):
            length = int(prefix[:-1])
            if not 1 <= length <= MAX_FRAME:
                raise ValueError("invalid frame size")
            return await reader.readexactly(length)
    try:
        rest = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError:
        raise ValueError("unterminated TCP frame; use LF or octet-counting")
    frame = (prefix + rest).rstrip(b"\r\n")
    if len(frame) > MAX_FRAME:
        raise ValueError("frame exceeds limit")
    return frame


class DatagramReceiver(asyncio.DatagramProtocol):
    def __init__(self, outbox, options, networks):
        self.outbox, self.options, self.networks = outbox, options, networks

    def datagram_received(self, data, addr):
        if not allowed(addr[0], self.networks):
            return
        try:
            self.outbox.append([record_bytes(data, self.options, "syslog_udp", addr[0])])
        except Exception as exc:
            LOG.error("UDP record was not queued: %s", type(exc).__name__)


def collect_file_once(path, outbox, options, follow=False):
    path = Path(path).resolve()
    key = "file:" + options.source + ":" + str(path)
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        identity = f"{stat.st_dev}:{stat.st_ino}"
        saved = outbox.checkpoint(key)
        offset = saved["offset"] if saved and saved["identity"] == identity else 0
        if stat.st_size < offset:
            offset = 0
        stream.seek(offset)
        count = 0
        # Bound each pass so forwarding and shutdown can make progress.
        for _ in range(500):
            line = stream.readline(MAX_FRAME + 2)
            if not line:
                break
            if follow and not line.endswith(b"\n") and len(line) <= MAX_FRAME:
                break  # Finish a partial line on the next pass.
            data = line.rstrip(b"\r\n")
            if len(data) > MAX_FRAME:
                raise ValueError("file line exceeds 65536 bytes; checkpoint remains before line")
            records = [record_bytes(data, options, "file")] if data else []
            outbox.append(records, (key, {"identity": identity, "offset": stream.tell()}))
            count += 1
        return count


def collect_cloudwatch(client, groups, outbox, options):
    count = 0
    for group in groups:
        key = "cloudwatch:" + options.source + ":" + options.region + ":" + group
        saved = outbox.checkpoint(key)
        end = int(time.time() * 1000)
        start = (
            max(0, saved["end"] - options.overlap_seconds * 1000)
            if saved
            else end - options.lookback_minutes * 60000
        )
        next_token = None
        while True:
            kwargs = {"logGroupName": group, "startTime": start, "endTime": end, "limit": 100}
            if next_token:
                kwargs["nextToken"] = next_token
            response = client.filter_log_events(**kwargs)
            records = []
            for event in response.get("events", []):
                data = event["message"].encode()
                record = record_bytes(data, options, "cloudwatch")
                record.record_id = hashlib.sha256(
                    (options.region + ":" + group + ":" + event["eventId"]).encode()
                ).hexdigest()
                record.host = options.host or (event.get("logStreamName") or "")[:256]
                record.attributes = {
                    "log_group": group,
                    "log_stream": event.get("logStreamName"),
                    "event_id": event["eventId"],
                    "timestamp_ms": event.get("timestamp"),
                    "region": options.region,
                }
                records.append(record)
            outbox.append(records)
            count += len(records)
            token = response.get("nextToken")
            if not token or token == next_token:
                break
            next_token = token
        # Only advance after every page is durable. Overlap replays use stable event IDs.
        outbox.append([], (key, {"end": end}))
    return count


async def forward(outbox, options, stop):
    delay = 1
    while not stop.is_set():
        try:
            sent = await asyncio.to_thread(outbox.deliver, options.api_url, options.token)
            delay = 1
            if sent:
                LOG.info("Forwarded %d records", sent)
                continue
        except Exception as exc:
            LOG.warning("Forwarding failed (%s); records retained in outbox", type(exc).__name__)
            delay = min(delay * 2, 30)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass


async def serve(options):
    outbox = Outbox(options.spool)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    task = asyncio.create_task(forward(outbox, options, stop))
    udp_transport, server, tls_receiver = None, None, None
    connections = set()
    try:
        if options.mode == "syslog":
            networks = [
                ipaddress.ip_network(item.strip()) for item in options.allowed_cidrs.split(",")
            ]
            tls = None
            if options.tls_cert:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.load_cert_chain(options.tls_cert, options.tls_key)

            async def accept(reader, writer):
                peer = writer.get_extra_info("peername")[0]
                if len(connections) >= 32 or not allowed(peer, networks):
                    writer.close()
                    await writer.wait_closed()
                    return
                current = asyncio.current_task()
                connections.add(current)
                try:
                    while not stop.is_set():
                        frame = await asyncio.wait_for(read_frame(reader), timeout=30)
                        if frame is None:
                            break
                        outbox.append(
                            [
                                record_bytes(
                                    frame, options, "syslog_tls" if tls else "syslog_tcp", peer
                                )
                            ]
                        )
                except (
                    ValueError,
                    asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError,
                    asyncio.TimeoutError,
                    OSError,
                ) as exc:
                    LOG.warning("TCP session closed (%s)", type(exc).__name__)
                finally:
                    connections.discard(current)
                    writer.close()
                    await writer.wait_closed()

            if tls:
                tls_receiver = TLSReceiver(
                    options.bind,
                    options.port,
                    tls,
                    lambda peer: allowed(peer, networks),
                    lambda frame, peer: outbox.append(
                        [record_bytes(frame, options, "syslog_tls", peer)]
                    ),
                )
            else:
                server = await asyncio.start_server(
                    accept, options.bind, options.port, limit=MAX_FRAME + 1
                )
            if not options.no_udp:
                udp_transport, _ = await loop.create_datagram_endpoint(
                    lambda: DatagramReceiver(outbox, options, networks),
                    local_addr=(options.bind, options.port),
                )
            LOG.info("Syslog listening on %s:%s", options.bind, options.port)
            await stop.wait()
        elif options.mode == "file":
            while not stop.is_set():
                count = await asyncio.to_thread(
                    collect_file_once, options.path, outbox, options, options.follow
                )
                if not options.follow and count < 500:
                    # One-shot waits for durable HTTP delivery, failing visibly on outage.
                    while await asyncio.to_thread(outbox.deliver, options.api_url, options.token):
                        pass
                    break
                await asyncio.sleep(0.5)
        elif options.mode == "cloudwatch":
            import boto3

            client = boto3.client("logs", region_name=options.region)
            while not stop.is_set():
                try:
                    await asyncio.to_thread(
                        collect_cloudwatch, client, options.log_group, outbox, options
                    )
                except Exception as exc:
                    LOG.warning("CloudWatch poll failed (%s); cursor retained", type(exc).__name__)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=options.poll_seconds)
                except asyncio.TimeoutError:
                    pass
    finally:
        stop.set()
        if udp_transport:
            udp_transport.close()
        if tls_receiver:
            await asyncio.to_thread(tls_receiver.close)
        if server:
            server.close()
            await server.wait_closed()
        for connection in list(connections):
            connection.cancel()
        await asyncio.gather(*connections, return_exceptions=True)
        await task


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default=os.getenv("DART_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--spool", default="data/collector.db")
    parser.add_argument("--source", required=True)
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--host")
    parser.add_argument(
        "--asset-type",
        default="other",
        choices=["network", "security", "server", "application", "cloud", "other"],
    )
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument(
        "--format", default="auto", choices=["auto", "syslog", "cef", "json", "kv", "text"]
    )
    modes = parser.add_subparsers(dest="mode", required=True)
    syslog = modes.add_parser("syslog")
    syslog.add_argument("--bind", default="127.0.0.1")
    syslog.add_argument("--port", type=int, default=5514)
    syslog.add_argument("--allowed-cidrs", default="127.0.0.1/32,::1/128")
    syslog.add_argument("--tls-cert")
    syslog.add_argument("--tls-key")
    syslog.add_argument("--no-udp", action="store_true")
    file = modes.add_parser("file")
    file.add_argument("path")
    file.add_argument("--follow", action="store_true")
    aws = modes.add_parser("cloudwatch")
    aws.add_argument("--region", required=True)
    aws.add_argument("--log-group", required=True, action="append")
    aws.add_argument("--poll-seconds", type=int, default=30)
    aws.add_argument("--lookback-minutes", type=int, default=60)
    aws.add_argument("--overlap-seconds", type=int, default=300)
    options = parser.parse_args()
    options.token = os.getenv("DART_API_TOKEN", "")
    if len(options.token) < 24:
        parser.error("set DART_API_TOKEN to at least 24 characters")
    parsed = urlparse(options.api_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        parser.error("api-url must be an HTTP(S) URL without embedded credentials")
    if options.mode == "syslog" and bool(options.tls_cert) != bool(options.tls_key):
        parser.error("tls-cert and tls-key must be provided together")
    if (
        options.mode == "cloudwatch"
        and min(options.poll_seconds, options.lookback_minutes, options.overlap_seconds) <= 0
    ):
        parser.error("CloudWatch timing values must be positive")
    # Validate metadata before opening sockets or creating a checkpoint.
    record_bytes(b"startup-validation", options, "http")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(serve(options))


if __name__ == "__main__":
    main()
