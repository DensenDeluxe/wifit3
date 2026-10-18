"""Parse the committed WPA3-Enterprise beacon PCAP and assert the RSN/AKM classification
per BSSID -- an end-to-end check over the pcap read + parser path. Regenerate the fixture
with tests/fixtures/make_wpa3_enterprise_pcap.py."""
from pathlib import Path

import pytest

from wifit3.dot11.parser import WlanFrameParser
from wifit3.persist.pcap import read_pcap, write_pcap

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
# The same seven profiles, two provenances: deterministic-synthetic and captured over the air.
_FIXTURES = {
    "synthetic": _FIXTURES_DIR / "wpa3_enterprise.pcap",
    "ota": _FIXTURES_DIR / "wpa3_enterprise_ota.pcap",
}

# BSSID -> (encryption label, wpa3, transition_mode) the parser must produce.
EXPECTED = {
    "02:73:a3:00:00:01": ("WPA2-EAP-CCMP", False, False),
    "02:73:a3:00:00:02": ("WPA3-EAP-SHA256-CCMP", True, False),
    "02:73:a3:00:00:03": ("WPA2/WPA3-EAP+EAP-SHA256-CCMP", True, True),
    "02:73:a3:00:00:04": ("WPA3-EAP-SUITE-B-192-GCMP-256", True, False),
    "02:73:a3:00:00:05": ("WPA2-EAP-SHA256-CCMP", False, False),
    "02:73:a3:00:00:06": ("WPA2-EAP-SUITE-B-192-GCMP-256", False, False),
    "02:73:a3:00:00:07": ("WPA2-EAP-SUITE-B-192-GCMP-256", False, False),
}


@pytest.fixture(scope="module", params=list(_FIXTURES), ids=list(_FIXTURES))
def parsed(request):
    out = {}
    for raw, _ts in read_pcap(_FIXTURES[request.param]):
        packet = WlanFrameParser.parse_80211_frame(raw, -50)
        out[packet.bssid] = packet
    return out


def test_pcap_contains_every_profile(parsed):
    assert set(parsed) == set(EXPECTED)


@pytest.mark.parametrize("bssid", list(EXPECTED))
def test_wpa3_enterprise_classification_from_pcap(parsed, bssid):
    packet = parsed[bssid]
    encryption, wpa3, transition = EXPECTED[bssid]
    assert packet.encryption == encryption
    assert packet.wpa3 is wpa3
    assert packet.transition_mode is transition


def test_read_pcap_roundtrips_write_pcap(tmp_path):
    frames = [(b"\x80\x00\x00\x00frame-one", 1_700_000_000.5),
              (b"\xff\xffframe-two", 1_700_000_001.25)]
    path = tmp_path / "roundtrip.pcap"
    assert write_pcap(path, frames) == 2
    back = read_pcap(path)
    assert [f for f, _ in back] == [f for f, _ in frames]
    assert back[0][1] == pytest.approx(1_700_000_000.5, abs=1e-6)


def test_read_pcap_empty_file_is_empty(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    assert read_pcap(empty) == []
