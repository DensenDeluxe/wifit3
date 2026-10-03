"""Factory-default PSK surfacing through the shared CaptureEventDetector.

crack/default_keys recovers the passphrase; this covers the *integration*: a
captured handshake makes the detector emit one DEFAULT_PSK event (once per AP),
and the Vault persists it as a WPA_PSK capture so has_psk/known_psk pick it up
exactly like a WPS- or hashcat-recovered key.
"""
from __future__ import annotations

from wifit3.crack import default_keys as dk
from wifit3.crack import wpa_psk
from wifit3.dot11.mac import str_to_mac
from wifit3.models import AccessPoint, Handshake, HandshakeMessage
from wifit3.persist.vault import Vault
from wifit3.ui.capture_events import CaptureEventDetector, CaptureKind

# An OTE conn-x AP whose default key is pinned in the Router Keygen vectors.
# BSSID lower-cased, as every AP coming off the sink is (dot11.mac.mac_to_str).
_SSID = "OTEcb4c"
_BSSID = "00:13:33:37:cb:4c"
_KEY = "000133337cb4c"
_CLIENT = "11:22:33:44:55:66"
_ANONCE = b"\xaa" * 32
_SNONCE = b"\x02" * 32


def _oracle(ssid: str, bssid: str, psk: str) -> Handshake:
    """A crackable M1+M2 whose M2 MIC is the one a station using ``psk`` would send."""
    aa, spa = str_to_mac(bssid), str_to_mac(_CLIENT)
    payload = bytearray(121)
    mic = wpa_psk.mic_for(psk, ssid, aa, spa, _ANONCE, _SNONCE, bytes(payload))
    payload[81:97] = mic
    m1 = HandshakeMessage(raw=b"", msg_num=1, replay_hex=(5).to_bytes(8, "big").hex(),
                          nonce=_ANONCE, mic=b"\x00" * 16, key_data_len=0, eapol_payload=bytes(121))
    m2 = HandshakeMessage(raw=b"", msg_num=2, replay_hex=(5).to_bytes(8, "big").hex(),
                          nonce=_SNONCE, mic=mic, key_data_len=0, eapol_payload=bytes(payload))
    return Handshake(bssid=bssid, client_mac=_CLIENT, beacon_frame=b"B", messages=[m1, m2])


def _ap_with_oracle(ssid: str, bssid: str, psk: str) -> AccessPoint:
    ap = AccessPoint(bssid=bssid, ssid=ssid)
    hs = _oracle(ssid, bssid, psk)
    ap.handshakes[hs.client_mac] = hs
    return ap


def test_detector_emits_default_psk_once():
    det = CaptureEventDetector(granular_eapol=False)
    ap = _ap_with_oracle(_SSID, _BSSID, _KEY)

    events = [e for e in det.poll(ap) if e.kind == CaptureKind.DEFAULT_PSK]
    assert len(events) == 1
    ev = events[0]
    assert ev.value == _KEY
    assert ev.bssid == _BSSID and ev.ssid == _SSID
    assert ev.family == dk.candidates(_SSID, _BSSID)[0][1]
    assert ap.default_psk == _KEY

    # Second poll: recovery ran, so no repeat (one-shot per AP).
    assert not any(e.kind == CaptureKind.DEFAULT_PSK for e in det.poll(ap))


def test_detector_skips_non_family_ssid():
    det = CaptureEventDetector(granular_eapol=False)
    # A verifiable handshake, but "HomeNet" matches no default-key family.
    ap = _ap_with_oracle("HomeNet", _BSSID, "whatever")
    assert not any(e.kind == CaptureKind.DEFAULT_PSK for e in det.poll(ap))
    assert ap.default_psk is None


def test_detector_waits_for_an_oracle():
    det = CaptureEventDetector(granular_eapol=False)
    ap = AccessPoint(bssid=_BSSID, ssid=_SSID)  # right family, but no handshake yet
    assert not any(e.kind == CaptureKind.DEFAULT_PSK for e in det.poll(ap))
    assert ap.default_psk is None
    # The recovery is not marked tried, so it still fires once the handshake lands.
    hs = _oracle(_SSID, _BSSID, _KEY)
    ap.handshakes[hs.client_mac] = hs
    assert sum(e.kind == CaptureKind.DEFAULT_PSK for e in det.poll(ap)) == 1


def test_vault_persists_default_psk_as_wpa_psk():
    ap = AccessPoint(bssid=_BSSID, ssid=_SSID)
    vault = Vault()
    assert vault.has_psk(ap) is False

    result = vault.save_wpa_psk(ap, _KEY)
    assert result is not None and result.was_new
    assert result.path.name.endswith("_wpa_psk.txt")

    assert vault.has_psk(ap) is True
    assert vault.known_psk(ap) == _KEY
    assert "WPA PSK" in vault.detailed_summary(ap)

    # Idempotent: saving the same key again is a dedupe hit, not a second file.
    again = vault.save_wpa_psk(ap, _KEY)
    assert again is not None and again.was_new is False
    assert again.path == result.path

    # A fresh Vault re-scans the file off disk and classifies it as WPA_PSK.
    assert Vault().known_psk(ap) == _KEY
