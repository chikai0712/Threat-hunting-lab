"""Bounded TLS syslog listener using blocking SSL sockets across supported Python versions.

A dedicated thread per connection drains decrypted frames before TLS shutdown;
this avoids older asyncio SSL transports discarding buffered data at close_notify.
"""

import logging
import socket
import socketserver
import threading

LOG = logging.getLogger("threat-log-collector")
MAX_FRAME = 65536


def read_frame(stream):
    first = stream.read(1)
    if not first:
        return None
    prefix = first
    if first.isdigit():
        while prefix[-1:].isdigit():
            if len(prefix) > 5:
                raise ValueError("invalid octet-counted frame length")
            char = stream.read(1)
            if not char:
                raise ValueError("incomplete frame length")
            prefix += char
        if prefix.endswith(b" "):
            length = int(prefix[:-1])
            if not 1 <= length <= MAX_FRAME:
                raise ValueError("invalid frame size")
            frame = stream.read(length)
            if len(frame) != length:
                raise ValueError("incomplete octet-counted frame")
            return frame
    rest = stream.readline(MAX_FRAME + 1)
    if not rest.endswith(b"\n"):
        raise ValueError("unterminated or oversized frame")
    frame = (prefix + rest).rstrip(b"\r\n")
    if len(frame) > MAX_FRAME:
        raise ValueError("oversized frame")
    return frame


class TLSReceiver:
    def __init__(self, bind, port, context, allowed, receive):
        connections, lock = set(), threading.Lock()
        slots = threading.BoundedSemaphore(32)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                connection = self.request
                with lock:
                    connections.add(connection)
                try:
                    connection.settimeout(30)
                    secured = context.wrap_socket(connection, server_side=True)
                    with lock:
                        connections.discard(connection)
                        connections.add(secured)
                    connection = secured
                    with connection.makefile("rb") as stream:
                        while True:
                            frame = read_frame(stream)
                            if frame is None:
                                break
                            receive(frame, self.client_address[0])
                    # Reply to a clean TLS close_notify after all complete frames were queued.
                    connection.unwrap().close()
                except Exception as exc:
                    LOG.warning("TLS session closed (%s)", type(exc).__name__)
                finally:
                    with lock:
                        connections.discard(connection)
                    connection.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

            def process_request(self, request, address):
                if not allowed(address[0]) or not slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except Exception:
                    slots.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    slots.release()

        self.server = Server((bind, port), Handler)
        self.connections, self.lock = connections, lock
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        )
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            for connection in list(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        self.thread.join(timeout=2)
