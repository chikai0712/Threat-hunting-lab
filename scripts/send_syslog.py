"""Send synthetic UDP and TCP device logs to a local collector."""

import socket

messages = [
    b'<189>date=2026-11-04 time=12:00:00 devname="lab-fortigate" action="deny" msg="synthetic test"',
    b"<134>1 2026-11-04T12:00:00Z lab-firewall app - - - CEF:0|Lab|Firewall|1|42|Synthetic block|7|src=192.0.2.1 dst=198.51.100.2",
    b"<166>Nov  4 12:00:00 lab-cisco %LINK-3-UPDOWN: synthetic interface event",
]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    for message in messages:
        udp.sendto(message, ("127.0.0.1", 5514))
with socket.create_connection(("127.0.0.1", 5514), timeout=5) as tcp:
    for message in messages:
        tcp.sendall(str(len(message)).encode() + b" " + message)
print("Sent 3 UDP and 3 TCP synthetic records. Check GET /logs?source=network-lab")
