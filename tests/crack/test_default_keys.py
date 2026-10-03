"""Factory-default WPA key recovery (crack/default_keys.py).

The generators are pinned byte-for-byte to the Router Keygen reference vectors
(data/default_keys_vectors.json). The end-to-end tests synthesise a vulnerable AP: compute the
family's default key, build a real 4-way MIC / PMKID with it (via crack.wpa_psk), then prove
``recover`` gets the passphrase back and rejects a non-default network.
"""

import json
from pathlib import Path

import pytest

from wifit3.crack import default_keys as dk
from wifit3.crack import wpa_psk
from wifit3.dot11.mac import str_to_mac
from wifit3.models import Handshake, HandshakeMessage

_VEC = json.loads((Path(__file__).parent / "data" / "default_keys_vectors.json").read_text())
_CASES = [(c["ssid"], c["bssid"], c["keys"])
          for fam, cases in _VEC.items() if fam != "_provenance" for c in cases]


@pytest.mark.parametrize("ssid, bssid, keys", _CASES)
def test_generator_matches_reference_vectors(ssid, bssid, keys):
    assert [psk for psk, _family in dk.candidates(ssid, bssid)] == keys


def test_unknown_ssid_yields_no_candidates():
    assert dk.candidates("MyHomeNetwork", "00:11:22:33:44:55") == []
    assert dk.candidates(None, "00:11:22:33:44:55") == []


def test_family_attribution():
    assert dk.candidates("Arcor-910B02", "00:12:BF:91:0B:EC")[0][1] == "Arcadyan/EasyBox"
    assert dk.candidates("INFINITUM1be2", "64:16:F0:35:1C:FD")[0][1] == "Huawei/INFINITUM"


# ----- end-to-end: synthesise a vulnerable AP, then recover its key ----------

_ANONCE = b"\xaa" * 32
_SNONCE = b"\x02" * 32
_CLIENT = "11:22:33:44:55:66"


def _handshake_with_psk(ssid, bssid, psk, client=_CLIENT):
    """A crackable M1+M2 whose M2 MIC is the real one a station with ``psk`` would send."""
    aa, spa = str_to_mac(bssid), str_to_mac(client)
    payload = bytearray(121)
    mic = wpa_psk.mic_for(psk, ssid, aa, spa, _ANONCE, _SNONCE, bytes(payload))
    payload[81:97] = mic
    m1 = HandshakeMessage(raw=b"", msg_num=1, replay_hex=(5).to_bytes(8, "big").hex(),
                          nonce=_ANONCE, mic=b"\x00" * 16, key_data_len=0, eapol_payload=bytes(121))
    m2 = HandshakeMessage(raw=b"", msg_num=2, replay_hex=(5).to_bytes(8, "big").hex(),
                          nonce=_SNONCE, mic=mic, key_data_len=0, eapol_payload=bytes(payload))
    return Handshake(bssid=bssid, client_mac=client, beacon_frame=b"B", messages=[m1, m2])


def _handshake_with_pmkid(ssid, bssid, psk, client=_CLIENT):
    aa, spa = str_to_mac(bssid), str_to_mac(client)
    return Handshake(bssid=bssid, client_mac=client, beacon_frame=b"B",
                     pmkid=dk.pmkid_for(psk, ssid, aa, spa))


def test_recover_from_4way_mic():
    ssid, bssid, keys = "Arcor-910B02", "00:12:BF:91:0B:EC", ["F9C8C9DEF"]
    hs = _handshake_with_psk(ssid, bssid, keys[0])
    assert dk.recover(ssid, bssid, hs) == (keys[0], "Arcadyan/EasyBox")


def test_recover_second_candidate_from_mic():
    # VodafoneGG11's real key is the SECOND Arcadyan candidate; the verifier must pick it.
    ssid, bssid = "VodafoneGG11", "74:31:70:33:00:11"
    real = dk.candidates(ssid, bssid)[1][0]        # "58639129A"
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "Arcadyan/EasyBox")


def test_recover_from_pmkid():
    ssid, bssid = "INFINITUM1be2", "64:16:F0:35:1C:FD"
    psk = dk.candidates(ssid, bssid)[0][0]
    hs = _handshake_with_pmkid(ssid, bssid, psk)
    assert dk.recover(ssid, bssid, hs) == (psk, "Huawei/INFINITUM")


def test_non_default_network_is_not_recovered():
    # Right family/SSID shape, but the AP's key was changed from the factory default.
    ssid, bssid = "Arcor-910B02", "00:12:BF:91:0B:EC"
    hs = _handshake_with_psk(ssid, bssid, "a-different-passphrase")
    assert dk.recover(ssid, bssid, hs) is None


def test_no_family_match_is_not_recovered():
    hs = _handshake_with_psk("MyHomeNetwork", "00:11:22:33:44:55", "whatever12")
    assert dk.recover("MyHomeNetwork", "00:11:22:33:44:55", hs) is None


def test_recover_belkin_from_mic():
    ssid, bssid = "Belkin_C0DE", "94:44:52:00:C0:DE"
    psk = dk.candidates(ssid, bssid)[0][0]       # "040D93B0"
    hs = _handshake_with_psk(ssid, bssid, psk)
    assert dk.recover(ssid, bssid, hs) == (psk, "Belkin")


def test_recover_sitecom_multicandidate_from_mic():
    # Sitecom yields 4 candidates; plant the 3rd as the real key -> the verifier must find it.
    ssid, bssid = "Sitecom", "00:0C:F6:01:2F:FE"
    real = dk.candidates(ssid, bssid)[2][0]
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "Sitecom")


def test_arnet_pirelli_reference_indices():
    # The full 7-candidate list isn't reference-pinned; assert exactly the indices upstream checks.
    arnet = dk.candidates("WiFi-Arnet-0184", "74:88:8B:27:2B:F4")
    assert len(arnet) == 7 and arnet[0][0] == "hcckr5ch38" and arnet[3][0] == "781haylokm"
    assert arnet[0][1] == "Arnet/Pirelli"
    adslpt = [p for p, _ in dk.candidates("ADSLPT-AB65637", "f0:84:2f:83:56:a2")]
    assert len(adslpt) == 7 and adslpt[0] == "ds7prly5"


def test_recover_arnet_from_mic():
    ssid, bssid = "WiFi-Arnet-0184", "74:88:8B:27:2B:F4"
    real = dk.candidates(ssid, bssid)[3][0]       # plant the 4th candidate
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "Arnet/Pirelli")


_ALICE_IT = [
    ("Alice-53847953", "00:25:53:35:a7:91", 1, 0, "7nfyuqlahytaml3bkcjasmtf"),
    ("Alice-37588990", "00:23:8e:48:e7:d4", 4, 3, "9j4hm3ojq4brfdy6wcsuglwu"),
    ("Alice-95535232", "00:8c:54:07:de:08", 1, 0, "e3eudsvbuu2i8zz2yalosd65"),
    ("Alice-53023425", "00:25:53:05:e3:50", 4, 3, "gi0wdaa3crf6wsb53sf7bv5t"),
]


@pytest.mark.parametrize("ssid, bssid, n, idx, key", _ALICE_IT)
def test_alice_italy_reference_indices(ssid, bssid, n, idx, key):
    cands = dk.candidates(ssid, bssid)
    assert len(cands) == n
    assert cands[idx] == (key, "Alice Italy")


def test_recover_alice_italy_from_mic():
    ssid, bssid = "Alice-53847953", "00:25:53:35:a7:91"
    real = dk.candidates(ssid, bssid)[0][0]
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "Alice Italy")


def test_recover_teletu_from_mic():
    ssid, bssid = "TeleTu_00238EE528C7", "00:23:8E:E5:28:C7"
    real = dk.candidates(ssid, bssid)[0][0]
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "TeleTu/Tele2")


def test_recover_upc_ubee_from_mic():
    ssid, bssid = "UPC5684389", "64:7C:34:3C:ff:63"
    real = dk.candidates(ssid, bssid)[0][0]
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "UPC/Ubee")


def test_bssid_tplink_engine():
    # "tplink" matches via MAC prefix in the reference matcher (not SSID), so exercise the engine.
    assert dk._bssid_transform("F8D1111E28A5", dk._UC | dk._LEN8, 0) == ["111E28A5"]


def test_recover_claro_multicandidate_from_mic():
    ssid, bssid = "Claro-7296", "C4:12:F5:38:72:96"
    real = dk.candidates(ssid, bssid)[1][0]        # the lowercase candidate
    hs = _handshake_with_psk(ssid, bssid, real)
    assert dk.recover(ssid, bssid, hs) == (real, "Claro")
