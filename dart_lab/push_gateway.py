"""Environment-routed Syslog listener with durable local buffering."""

import asyncio
import base64
import logging

from .collector import Outbox, read_frame, MAX_FRAME
from .models import LogRecord
from .sources import PROFILES

LOG = logging.getLogger("source-push")


class PushGateway:
    def __init__(self, settings, store):
        self.settings, self.store = settings, store
        self.outbox = Outbox(settings.spool)
        self.stop = None
        self.server, self.udp, self.worker = None, None, None
        self.connections = set()

    def enqueue(self, data, peer, transport):
        source = self.settings.source_for(peer)
        if not source or not data or len(data) > MAX_FRAME:
            return False
        _, vendor, product, asset = PROFILES[source]
        self.outbox.append(
            [
                LogRecord(
                    source=source,
                    raw=data.decode("utf-8", errors="replace"),
                    raw_base64=base64.b64encode(data).decode(),
                    peer=peer,
                    transport=transport,
                    vendor=vendor,
                    product=product,
                    asset_type=asset,
                )
            ]
        )
        return True

    async def accept(self, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        if not self.settings.source_for(peer) or len(self.connections) >= 32:
            writer.close()
            await writer.wait_closed()
            return
        current = asyncio.current_task()
        self.connections.add(current)
        try:
            while not self.stop.is_set():
                frame = await asyncio.wait_for(read_frame(reader), timeout=30)
                if frame is None:
                    break
                self.enqueue(frame, peer, "syslog_tcp")
        except (
            ValueError,
            OSError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            asyncio.TimeoutError,
        ) as exc:
            LOG.warning("Source TCP session closed (%s)", type(exc).__name__)
        finally:
            self.connections.discard(current)
            writer.close()
            await writer.wait_closed()

    def drain_once(self):
        batch = self.outbox.batch()
        if not batch:
            return False
        self.store.ingest_logs([LogRecord.model_validate(record) for _, record in batch])
        self.outbox.acknowledge([identity for identity, _ in batch])
        return True

    async def drain(self):
        while not self.stop.is_set():
            try:
                if await asyncio.to_thread(self.drain_once):
                    continue
            except Exception as exc:
                LOG.error(
                    "Normalization failed (%s); source logs retained in outbox", type(exc).__name__
                )
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=1)
            except asyncio.TimeoutError:
                pass

    async def start(self):
        self.stop = asyncio.Event()
        gateway = self

        class UDP(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    gateway.enqueue(data, addr[0], "syslog_udp")
                except Exception as exc:
                    LOG.error("Unable to queue UDP log (%s)", type(exc).__name__)

        try:
            self.server = await asyncio.start_server(
                self.accept,
                self.settings.syslog_bind,
                self.settings.syslog_port,
                limit=MAX_FRAME + 1,
            )
            self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                UDP, local_addr=(self.settings.syslog_bind, self.settings.syslog_port)
            )
            self.worker = asyncio.create_task(self.drain())
        except Exception:
            await self.close()
            raise

    async def close(self):
        if self.stop:
            self.stop.set()
        if self.udp:
            self.udp.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        connections = list(self.connections)
        for task in connections:
            task.cancel()
        await asyncio.gather(*connections, return_exceptions=True)
        if self.worker:
            await self.worker
