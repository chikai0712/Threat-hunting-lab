"""Run the actual .env entrypoint, verify HTTP and source-routed Syslog push."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dart_lab.sources import PROFILES

TOKEN = "env-server-test-token-not-for-production"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_env_only_server_routes_http_and_syslog(tmp_path):
    http_port, syslog_port = free_port(), free_port()
    while http_port == syslog_port:
        syslog_port = free_port()
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"DART_API_TOKEN={TOKEN}\nDART_DB_PATH={tmp_path / 'data.db'}\n"
        f"SOURCE_PUSH_SPOOL={tmp_path / 'spool.db'}\nLISTEN_IP=127.0.0.1\n"
        f"HTTP_PORT={http_port}\nSYSLOG_PORT={syslog_port}\nFORTINET_IPS=127.0.0.1\n"
        "SYSLOG_ENABLED=true\nSOURCE_PUSH_REQUIRE_TOKEN=false\n"
    )
    env = dict(os.environ)
    for key in (
        "DART_API_TOKEN",
        "DART_DB_PATH",
        "SOURCE_PUSH_SPOOL",
        "LISTEN_IP",
        "HTTP_PORT",
        "SYSLOG_PORT",
        "SYSLOG_BIND_IP",
        "SYSLOG_ENABLED",
        "SOURCE_PUSH_REQUIRE_TOKEN",
        *(profile[0] for profile in PROFILES.values()),
    ):
        env.pop(key, None)
    url = f"http://127.0.0.1:{http_port}"
    with (tmp_path / "service.log").open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "dart_lab.server"], cwd=tmp_path, env=env, stdout=log, stderr=log
        )

        def get(path, token=False):
            req = Request(url + path, headers={"X-API-Key": TOKEN} if token else {})
            with urlopen(req, timeout=2) as response:
                return json.load(response)

        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    if get("/health")["status"] == "ok":
                        break
                except URLError:
                    if process.poll() is not None:
                        raise AssertionError((tmp_path / "service.log").read_text())
                    time.sleep(0.1)
            else:
                raise AssertionError("Server did not start from .env")
            request = Request(
                url + "/api/v1/logs/fortinet",
                data=b"action=deny srcip=192.0.2.1",
                headers={"Content-Type": "text/plain"},
            )
            with urlopen(request, timeout=2) as response:
                result = json.load(response)
            assert result["records"][0]["normalized"]["source_ip"] == "192.0.2.1"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.sendto(b"<189>action=allow devname=fw1", ("127.0.0.1", syslog_port))
            with socket.create_connection(("127.0.0.1", syslog_port), timeout=2) as tcp:
                tcp.sendall(b"<189>action=deny devname=fw1\n")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                records = get("/logs", token=True)["items"]
                if len(records) == 3:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Syslog push records missing")
            assert {item["transport"] for item in records} == {"http", "syslog_udp", "syslog_tcp"}
            assert all(item["source"] == "fortinet" for item in records)
            # Even a permitted IP cannot access a different disabled source.
            try:
                urlopen(Request(url + "/api/v1/logs/cisco", data=b"test"), timeout=2)
                raise AssertionError("Disabled source accepted a record")
            except HTTPError as exc:
                assert exc.code == 403
        finally:
            process.terminate()
            process.wait(timeout=20)


def test_env_initializer_preserves_existing_file(tmp_path):
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "scripts/init_env.py"
    spec = importlib.util.spec_from_file_location("init_env", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    destination = tmp_path / ".env"
    template = tmp_path / ".env.example"
    template.write_text("DART_API_TOKEN=\nFORTINET_IPS=\n")
    assert module.initialize(destination, template)
    original = destination.read_text()
    assert len(original.splitlines()[0].split("=", 1)[1]) >= 24
    assert not module.initialize(destination, template)
    assert destination.read_text() == original
