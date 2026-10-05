"""Active decloak: send directed Probe Requests with sibling-derived SSID
candidates and let the existing passive decloak path catch the response."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Callable, Iterable, List, Optional

from wifit3.models import AccessPoint
from wifit3.campaigns.auth_assoc import Association, build_client_leaving
from wifit3.campaigns.campaign import Campaign
from wifit3.dot11 import mac_to_str, str_to_mac
from wifit3.dot11.probe import probe_req

logger = logging.getLogger(__name__)

_ASSOCIATION_FALLBACK_LIMIT = 32


# Curated suffix list, kept short on purpose so a full run is ~5 seconds.
SIBLING_SUFFIXES: List[str] = [
    "",
    "-Guest", "_Guest", "-guest", " Guest",
    "-5G", "_5G", "-5GHz",
    "-2G", "_2G", "-2.4G", "-2.4GHz",
    "-IoT", "_IoT",
    "-Setup", "_Setup",
    "-EXT",
]


def build_candidates(base: str) -> List[str]:
    """Generate likely sibling SSIDs given a known visible sibling's SSID."""
    if not base:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for suffix in SIBLING_SUFFIXES:
        cand = base + suffix
        if cand and len(cand.encode("utf-8")) <= 32 and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def expand_candidates(lines: Iterable[str], base: str,
                      max_candidates: Optional[int] = None) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, 1):
        if "$ssid" in line and not base:
            continue
        cand = line.replace("$ssid", base)
        octets = len(cand.encode("utf-8"))
        if octets > 32:
            raise ValueError(
                f"SSID on line {line_number} is {octets} UTF-8 bytes; maximum is 32"
            )
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
            if max_candidates is not None and len(out) > max_candidates:
                raise ValueError(f"At most {max_candidates} candidate SSIDs are allowed")
    return out


def _validate_candidates(candidates: Iterable[str]) -> List[str]:
    validated: List[str] = []
    for position, candidate in enumerate(candidates, 1):
        octets = len(candidate.encode("utf-8"))
        if octets > 32:
            raise ValueError(
                f"candidate {position} is {octets} UTF-8 bytes; maximum is 32"
            )
        if candidate:
            validated.append(candidate)
    return validated


def _random_client_mac() -> bytes:
    """Locally-administered, unicast MAC. LAA bit set, multicast bit clear."""
    rnd = os.urandom(5)
    return bytes([0x02]) + rnd


class DecloakAttack:
    """Run an active decloak probe sequence against a single hidden AP."""

    def __init__(
        self,
        array,
        target: AccessPoint,
        base_ssid: str,
        source_mac: Optional[bytes] = None,
        candidates_override: Optional[List[str]] = None,
        iface=None,
        association_fallback: bool = True,
    ):
        self.array = array
        self.target = target
        self.base_ssid = base_ssid
        self.bssid_bytes = str_to_mac(target.bssid)
        self.source_mac = source_mac or _random_client_mac()
        self.candidates_override = (
            _validate_candidates(candidates_override)
            if candidates_override is not None else None
        )
        self.iface = iface
        self.association_fallback = association_fallback
        self.tried = 0
        self.association_tried = 0
        self.array.register_forged_mac(self.source_mac)

    # ---- Driver -------------------------------------------------------------

    async def run(
        self,
        per_candidate_timeout: float = 0.3,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Optional[str]:
        iface = self.iface or self.array.select_iface(self.target.channel)
        if iface is None:
            logger.info("[DECLOAK] no card can reach channel %s for %s",
                        self.target.channel, self.target.bssid)
            return None
        if iface.current_channel != self.target.channel:
            tuned = await iface.set_channel(self.target.channel)
            if tuned is False:
                raise RuntimeError(f"card failed to tune to channel {self.target.channel}")

        candidates = (
            self.candidates_override
            if self.candidates_override is not None
            else build_candidates(self.base_ssid)
        )
        bssid_lower = self.target.bssid.lower()
        initial_ssid = self.array.access_points.get(bssid_lower, self.target).ssid

        src = ("explicit" if self.candidates_override is not None
               else f"base '{self.base_ssid}'")
        logger.info(
            f"[DECLOAK] {self.target.bssid}: trying {len(candidates)} candidates "
            f"({src}) as STA {mac_to_str(self.source_mac)}"
        )

        for candidate in candidates:
            if should_stop is not None and should_stop():
                logger.info("[DECLOAK] stop requested for %s", self.target.bssid)
                return None
            frame = probe_req(
                self.bssid_bytes, self.source_mac, candidate, channel=self.target.channel,
            )
            sent = await iface.send_no_wait(frame)
            if sent is False:
                raise RuntimeError(f"probe injection failed for candidate {candidate!r}")
            self.tried += 1

            # Poll briefly: the parser flips ap.ssid asynchronously when the AP echoes back a
            # Probe Response the sink's decloak guard sees.
            deadline = time.monotonic() + per_candidate_timeout
            while time.monotonic() < deadline:
                if should_stop is not None and should_stop():
                    return None
                ap_state = self.array.access_points.get(bssid_lower)
                if ap_state and ap_state.ssid and ap_state.ssid != initial_ssid:
                    logger.info(
                        f"[DECLOAK] hit on candidate '{candidate}' → "
                        f"{ap_state.ssid!r}"
                    )
                    return ap_state.ssid
                await asyncio.sleep(0.03)

        if self.association_fallback:
            revealed = await self._run_association_fallback(
                iface, candidates[:_ASSOCIATION_FALLBACK_LIMIT], should_stop,
            )
            if revealed is not None:
                return revealed

        logger.info(f"[DECLOAK] exhausted candidates for {self.target.bssid}")
        return None

    async def _run_association_fallback(
        self, iface, candidates: List[str], should_stop: Optional[Callable[[], bool]],
    ) -> Optional[str]:
        logger.info(
            "[DECLOAK] directed probes silent; trying association oracle for %d candidates",
            len(candidates),
        )
        control_ssid = self._association_control_ssid(candidates)
        control = await self._association_attempt(iface, control_ssid, should_stop)
        if control.associated:
            await self._leave_association(iface)
            logger.info(
                "[DECLOAK] association oracle disabled for %s: AP accepted control SSID",
                self.target.bssid,
            )
            return None
        if control.assoc_status is None:
            logger.info(
                "[DECLOAK] association oracle inconclusive for %s: control was not explicitly rejected",
                self.target.bssid,
            )
            return None
        for candidate in candidates:
            if should_stop is not None and should_stop():
                return None
            association = await self._association_attempt(iface, candidate, should_stop)
            self.association_tried += 1
            if association.associated:
                self.array.confirm_decloak(self.target.bssid, candidate, "assoc_oracle")
                await self._leave_association(iface)
                logger.info(
                    "[DECLOAK] association oracle accepted candidate %r for %s",
                    candidate, self.target.bssid,
                )
                return candidate
        return None

    def _association_control_ssid(self, candidates: List[str]) -> str:
        while True:
            control = f"wifit3-control-{os.urandom(8).hex()}"
            if control not in candidates:
                return control

    async def _association_attempt(self, iface, ssid: str, should_stop) -> Association:
        association = Association(
            iface,
            self.target.bssid,
            ssid,
            self.target.channel,
            our_mac=self.source_mac,
            auth_timeout=0.2,
            assoc_timeout=0.3,
            assoc_trailer_ies=self.target.rsn_ie or b"",
            privacy=(self.target.encryption or "OPEN").upper() != "OPEN",
            should_stop=should_stop,
        )
        association.start()
        try:
            await association.associate(attempts=1)
        finally:
            association.stop()
        return association

    async def _leave_association(self, iface) -> None:
        try:
            await iface.send_no_wait(build_client_leaving(self.bssid_bytes, self.source_mac))
        except Exception:
            logger.debug("[DECLOAK] failed to send client-leaving cleanup", exc_info=True)


class DecloakCampaign(Campaign):
    button_id = "btn-decloak"
    key = "decloak"
    hotkey = ("d", "Decloak")
    idle_label = "Decloak"
    run_label = "Stop Decloak"

    @classmethod
    def visible(cls, ap) -> bool:
        return ap.is_hidden

    def __init__(self, array, target, *, candidates: Optional[List[str]] = None,
                 base_ssid: str = "",
                 log: Optional[Callable[[str], None]] = None):
        super().__init__(ap=target, array=array)
        self.candidates = candidates
        self.base_ssid = base_ssid
        self._log = log or (lambda _m: None)
        self._attack: Optional[DecloakAttack] = None
        self.revealed: Optional[str] = None
        self.tried = 0

    def status_under_card(self) -> str:
        return "● Decloak"

    def status_headlines(self, vault) -> list[str]:
        total = len(
            self.candidates
            if self.candidates is not None else build_candidates(self.base_ssid)
        )
        return ["[bold cyan]● Decloak[/bold cyan] probing candidate SSIDs",
                f"[dim]{self.tried}/{total} sent[/dim]"]

    async def _loop(self) -> None:
        self._attack = DecloakAttack(
            self.array,
            self.ap,
            base_ssid=self.base_ssid,
            candidates_override=self.candidates,
            iface=self.iface,
        )
        try:
            self.revealed = await self._attack.run(should_stop=lambda: self.stopped)
        finally:
            self.tried = self._attack.tried

    async def teardown(self) -> None:
        if self._attack is not None:
            self.array.unregister_forged_mac(self._attack.source_mac)
