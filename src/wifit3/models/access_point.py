"""Scan-registry models: an access point and its per-AP sub-data (WEP IV counters,
previously-saved capture artifacts).
"""
import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Dict, List, Optional, Set

from wifit3.dot11.pmf import PmfPosture, classify_pmf, deauth_resistant
from wifit3.dot11.rsn import ENTERPRISE_AKM_SUITES

from .handshake import Handshake
from .identity import ApIdentity, IdKey, IdSource
from .security import Severity, SecurityWarning

_RSN_AKM_PREFIX = 0x000FAC00
_EAP_AKM_SELECTORS = frozenset(_RSN_AKM_PREFIX | suite for suite in ENTERPRISE_AKM_SUITES)


def _advertised_akm_selectors(ap) -> set[int]:
    selectors = set(getattr(ap, "akm_selectors", None) or ())
    if selectors:
        return selectors
    return {_RSN_AKM_PREFIX | suite for suite in (getattr(ap, "akm_suites", None) or ())}


def eap_only(ap) -> bool:
    """True when every advertised AKM is 802.1X/EAP or FILS (no PSK, no SAE)."""
    selectors = _advertised_akm_selectors(ap)
    if selectors:
        return selectors <= _EAP_AKM_SELECTORS
    akms = getattr(ap, "akms", None) or ()
    return bool(akms) and all(
        a.startswith("EAP") or a.startswith("FT-EAP") for a in akms
    )


_NO_PASSPHRASE_AKM_SUITES = ENTERPRISE_AKM_SUITES | frozenset({18})
_NO_PASSPHRASE_AKM_SELECTORS = frozenset(
    _RSN_AKM_PREFIX | suite for suite in _NO_PASSPHRASE_AKM_SUITES)


def no_passphrase(ap) -> bool:
    selectors = _advertised_akm_selectors(ap)
    if selectors:
        return selectors <= _NO_PASSPHRASE_AKM_SELECTORS
    akms = getattr(ap, "akms", None) or ()
    return bool(akms) and all(
        a.startswith("EAP") or a.startswith("FT-EAP") or a == "OWE" for a in akms
    )


def deauth_protected(ap) -> Optional[bool]:
    """Whether PMF rejects forged deauth/disassoc, or None for contradictory MFPC/MFPR."""
    posture = classify_pmf(
        bool(getattr(ap, "pmf_capable", False)),
        bool(getattr(ap, "pmf_required", False)))
    return deauth_resistant(posture)


def deauth_attack_allowed(ap) -> bool:
    """True only when the advertised PMF bits establish that forged deauth is viable."""
    return deauth_protected(ap) is False


@dataclass
class WepStats:
    """WEP IV counters for one AP: unique IVs and total WEP frames seen."""
    unique_ivs: int = 0
    total_frames: int = 0


class CaptureType(StrEnum):
    """Kind of a saved capture artifact, one member per on-disk file kind. Distinct
    from ui.capture_events.CaptureKind, which enumerates live detector events."""
    HS = "HS"
    PMKID = "PMKID"
    WEP = "WEP"
    WPS_PIN = "WPS_PIN"
    WPS_PBC = "WPS_PBC"
    WPA_PSK = "WPA_PSK"           # passphrase recovered from a handshake/PMKID (e.g. hashcat)


@dataclass
class PersistedCapture:
    """One previously-saved capture artifact found under captures/."""
    type: CaptureType
    timestamp: int                  # epoch seconds, parsed from the filename
    path: str                       # source file under captures/
    bssid: str                      # AP this capture belongs to (colon form)
    value: Optional[str] = None     # WEP key (hex) / WPS PSK; None for HS/PMKID
    ssid: Optional[str] = None      # parsed from the filename, for display (VAULT)
    pin: Optional[str] = None       # WPS PIN (WPS_PIN captures only)
    record_count: int = 1           # hashcat-22000 records in the file; 0 for raw .pcap


@dataclass
class AccessPoint:
    bssid: str
    ssid: Optional[str] = None
    channel: int = 1
    encryption: Optional[str] = "Unknown"
    # Structured security fields from the RSN IE; `encryption` (above) is the airodump-style string.
    akms: List[str] = field(default_factory=list)
    # 00-0F-AC suite types; vendor-specific selectors are only in `akm_selectors`.
    akm_suites: List[int] = field(default_factory=list)
    # Complete four-octet AKM selectors, including vendor OUIs and unknown standard suites.
    akm_selectors: List[int] = field(default_factory=list)
    rsn_valid: bool = False
    pairwise_cipher: Optional[str] = None
    beacons: int = 0
    first_seen: float = field(default_factory=time.time)
    # Most recent beacon/probe-resp timestamp.
    last_seen: float = field(default_factory=time.time)
    wpa3: bool = False
    transition_mode: bool = False
    wpa3_enterprise_transition_profile: bool = False
    pmf_capable: bool = False
    pmf_required: bool = False
    beacon_protection: bool = False
    # Passively observed EAP method Type numbers (EAPOL-Type-0), aggregated across clients.
    observed_eap_methods: Set[int] = field(default_factory=set)

    # WPS state decoded from the WPS vendor IE (tag 221, OUI 00:50:F2 type 4).
    wps: bool = False
    wps_locked: bool = False
    wps_version: Optional[str] = None  # "1.0" / "2.0"
    wps_config_methods: int = 0  # 0x1008 bitmask
    wps_device_password_id: Optional[int] = None  # 0x0004 = PBC
    identity: ApIdentity = field(default_factory=ApIdentity)
    # Set while the AP is advertising an active Registrar (PIN or, with
    # DevPwId 0x0004, a Push-Button walk window). Drives wps_pbc_active.
    wps_selected_registrar: bool = False

    # Most recent raw beacon bytes.
    last_beacon_frame: Optional[bytes] = None

    # Raw RSN IE bytes (tag 48, incl. the 2-byte tag header) as advertised in the AP's beacons.
    rsn_ie: Optional[bytes] = None

    # How this AP's SSID was learned, if it was ever hidden.
    # None = we never saw it hidden, or it's still hidden.
    decloak_method: Optional[str] = None

    # BSSIDs we believe are virtual interfaces of the same physical radio (Main + Guest +
    # IoT on one router). Bidirectional.
    siblings: List[str] = field(default_factory=list)

    # Per-client handshake captures, keyed by client MAC (clients can capture simultaneously).
    handshakes: Dict[str, Handshake] = field(default_factory=dict)

    # WEP IV counters, populated for WEP APs on the first encrypted Data frame (None otherwise).
    wep: Optional[WepStats] = None

    # Recovered WEP key (the cracker's payoff).
    wep_key: Optional[bytes] = None

    # Recovered WPS PSK from a successful Push-Button (PBC) capture.
    wps_pbc_psk: Optional[str] = None

    # Recovered WPS PIN + the passphrase it yielded, from a successful PIN brute-force.
    # Kept distinct from wps_pbc_psk (PIN vs Push-Button).
    wps_pin: Optional[str] = None
    wps_pin_psk: Optional[str] = None

    # Smoothed RSSI per receiving card (card name -> dBm), written by WlanSink.
    signal_by_card: Dict[str, int] = field(default_factory=dict)
    signal_history: Dict[str, deque[int]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.bssid and not self.identity.get_source_value(IdKey.MANUFACTURER, IdSource.OUI):
            from wifit3.id.common import vendor_for_mac
            vendor = vendor_for_mac(self.bssid)
            if vendor:
                self.identity.set(IdSource.OUI, IdKey.MANUFACTURER, vendor)

    @property
    def signal(self) -> int:
        """Strongest smoothed RSSI (dBm) across the cards that hear this AP; -100 if none yet."""
        return max(self.signal_by_card.values(), default=-100)

    @property
    def wps_pbc_active(self) -> bool:
        """True during a WPS Push-Button walk window: the AP advertises PBC
        (Device Password ID 0x0004) with an active Selected Registrar."""
        return (
            self.wps
            and self.wps_selected_registrar
            and self.wps_device_password_id == 0x0004
        )

    @property
    def is_hidden(self) -> bool:
        """No usable SSID: never seen, or still the "<hidden>" placeholder."""
        return not (self.ssid and self.ssid != "<hidden>")

    @property
    def pmf_posture(self) -> PmfPosture:
        """802.11w posture derived from the advertised MFPC/MFPR bits."""
        return classify_pmf(self.pmf_capable, self.pmf_required)

    @property
    def security_warnings(self) -> List[SecurityWarning]:
        """PMF advisories for this AP; empty for non-RSN (open / WEP / WPA1) networks."""
        if not self.akm_suites and not self.akm_selectors:
            return []
        posture = self.pmf_posture
        out: List[SecurityWarning] = []
        if posture is PmfPosture.INVALID:
            out.append(SecurityWarning(
                "pmf-invalid", Severity.CRITICAL,
                "RSN sets MFPR without MFPC (malformed PMF configuration)"))
        elif posture is PmfPosture.DISABLED:
            out.append(SecurityWarning(
                "pmf-disabled", Severity.WARNING,
                "PMF disabled: management frames unprotected (deauth/disassoc succeed)"))
        elif posture is PmfPosture.OPTIONAL:
            out.append(SecurityWarning(
                "pmf-optional", Severity.WARNING,
                "PMF optional: non-PMF clients remain deauth/disassoc-vulnerable"))
        if self.wpa3 and not self.transition_mode and posture is not PmfPosture.REQUIRED:
            out.append(SecurityWarning(
                "wpa3-without-pmf", Severity.CRITICAL,
                "WPA3 advertised without required PMF (non-compliant, downgrade-exposed)"))
        in_transition = self.transition_mode or self.wpa3_enterprise_transition_profile
        if in_transition and not self.pmf_capable:
            out.append(SecurityWarning(
                "wpa3-transition-no-mfpc", Severity.CRITICAL,
                "WPA3 transition requires PMF-capable (MFPC); clearing it is invalid (downgrade-exposed)"))
        elif self.wpa3_enterprise_transition_profile and self.pmf_required:
            out.append(SecurityWarning(
                "wpa3-transition-mfpr", Severity.WARNING,
                "WPA3-Enterprise transition requires MFPR=0; setting it breaks the WPA2 fallback"))
        return out
