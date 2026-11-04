"""Real loopback sockets: collect during outage, restart, and forward from disk."""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest

from dart_lab.collector import Outbox

TOKEN = "live-test-token-not-for-production"


def wait_until(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for local integration service")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("tls", [False, True])
def test_socket_collection_outage_restart_and_recovery(tmp_path, tls):
    api_port, collector_port = free_port(), free_port()
    while api_port == collector_port:
        collector_port = free_port()
    url = f"http://127.0.0.1:{api_port}"
    spool = tmp_path / "outbox.db"
    outbox = Outbox(spool)
    env = dict(os.environ, DART_API_TOKEN=TOKEN, DART_DB_PATH=str(tmp_path / "api.db"))
    collector_command = [
        sys.executable,
        "-m",
        "dart_lab.collector",
        "--source",
        "socket-test",
        "--api-url",
        url,
        "--spool",
        str(spool),
        "syslog",
        "--port",
        str(collector_port),
    ]
    context = None
    if tls:
        if not shutil.which("openssl"):
            pytest.skip("TLS fixture requires openssl")
        cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        collector_command += ["--tls-cert", str(cert), "--tls-key", str(key), "--no-udp"]
        context = ssl.create_default_context(cafile=str(cert))
    processes = []
    with (tmp_path / "services.log").open("w") as output:

        def launch(command):
            process = subprocess.Popen(command, env=env, stdout=output, stderr=output)
            processes.append(process)
            return process

        def connect():
            connection = socket.create_connection(("127.0.0.1", collector_port), timeout=2)
            return (
                context.wrap_socket(connection, server_hostname="localhost") if tls else connection
            )

        def ready():
            try:
                with connect():
                    return True
            except OSError:
                return False

        def api_get(path):
            request = Request(url + path, headers={"X-API-Key": TOKEN})
            with urlopen(request, timeout=2) as response:
                return json.load(response)

        def api_ready():
            try:
                return api_get("/health")["status"] == "ok"
            except URLError:
                return False

        try:
            collector = launch(collector_command)
            wait_until(ready)
            expected = 2 if tls else 3
            if not tls:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.sendto(
                        b"<134>Nov  4 12:00:00 router UDP test", ("127.0.0.1", collector_port)
                    )
            with connect() as tcp:
                tcp.sendall(b"<134>Nov  4 12:00:00 router newline test\n")
                message = "<134>1 2026-11-04T12:00:00Z fw app - - - 中文測試".encode()
                wire = str(len(message)).encode() + b" " + message
                for start in range(0, len(wire), 3):
                    tcp.sendall(wire[start : start + 3])
            wait_until(lambda: len(outbox.batch()) == expected)
            collector.terminate()
            collector.wait(timeout=20)
            assert len(Outbox(spool).batch()) == expected
            launch(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "dart_lab.api:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                ]
            )
            wait_until(api_ready)
            launch(collector_command)
            wait_until(lambda: len(api_get("/logs")["items"]) == expected)
            wait_until(lambda: not outbox.batch())
            items = api_get("/logs")["items"]
            assert all(item["parsed"]["status"] == "parsed" for item in items)
            assert all(item["raw_base64"] for item in items)
            assert any("中文測試" in item["raw"] for item in items)
            if tls:
                assert all(item["transport"] == "syslog_tls" for item in items)
            else:
                assert {item["transport"] for item in items} == {"syslog_tcp", "syslog_udp"}
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
