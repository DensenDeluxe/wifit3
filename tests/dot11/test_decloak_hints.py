import binascii
import struct

from wifit3.dot11.packet import BeaconPacket, FilsDiscoveryPacket, SsidHint
from wifit3.dot11.parser import WlanFrameParser


BSSID = b"\x11\x22\x33\x44\x55\x66"


def _beacon(*ies: bytes, ssid: str = "Visible") -> bytes:
    header = b"\x80\x00\x00\x00" + b"\xff" * 6 + BSSID + BSSID + b"\x00\x00"
    fixed = b"\x00" * 8 + b"\x64\x00\x01\x00"
    ssid_bytes = ssid.encode()
    return header + fixed + bytes((0, len(ssid_bytes))) + ssid_bytes + b"\x01\x01\x82" + b"".join(ies)


def _ie(element_id: int, value: bytes) -> bytes:
    return bytes((element_id, len(value))) + value


def test_multiple_bssid_profile_exposes_nontransmitted_ssid():
    profile = _ie(83, b"\x00\x00") + _ie(0, b"Hidden-BSS") + _ie(85, b"\x01")
    frame = _beacon(_ie(71, b"\x03" + _ie(0, profile)))

    packet = WlanFrameParser.parse_80211_frame(frame, -40)

    assert isinstance(packet, BeaconPacket)
    assert packet.ssid_hints == [
        SsidHint(bssid="11:22:33:44:55:67", method="mbssid", ssid="Hidden-BSS")
    ]


def test_rnr_short_ssid_and_same_ssid_are_extracted():
    neighbor_a = b"\x00" + b"\xaa\xbb\xcc\xdd\xee\x01"
    neighbor_a += struct.pack("<I", binascii.crc32(b"Other") & 0xffffffff) + b"\x00"
    neighbor_b = b"\x00" + b"\xaa\xbb\xcc\xdd\xee\x02"
    neighbor_b += struct.pack("<I", binascii.crc32(b"Visible") & 0xffffffff) + b"\x02"
    rnr = bytes((0x10, 12, 131, 5)) + neighbor_a + neighbor_b

    packet = WlanFrameParser.parse_80211_frame(_beacon(_ie(201, rnr)), -40)

    assert [(hint.bssid, hint.method, hint.ssid, hint.short_ssid)
            for hint in packet.ssid_hints] == [
        ("aa:bb:cc:dd:ee:01", "rnr_short_ssid", None,
         binascii.crc32(b"Other") & 0xffffffff),
        ("aa:bb:cc:dd:ee:02", "rnr_same_ssid", "Visible", None),
    ]


def test_rnr_length_eleven_does_not_treat_short_ssid_byte_as_parameters():
    neighbor = b"\x00" + b"\xaa\xbb\xcc\xdd\xee\x03" + struct.pack("<I", 2)
    rnr = bytes((0x00, 11, 131, 5)) + neighbor

    packet = WlanFrameParser.parse_80211_frame(_beacon(_ie(201, rnr)), -40)

    assert [(hint.method, hint.ssid, hint.short_ssid) for hint in packet.ssid_hints] == [
        ("rnr_short_ssid", None, 2)
    ]


def test_owe_transition_ie_exposes_open_partner():
    peer = b"\xaa\xbb\xcc\xdd\xee\xff"
    owe = b"\x50\x6f\x9a\x1c" + peer + b"\x09Cafe-WiFi"

    packet = WlanFrameParser.parse_80211_frame(_beacon(_ie(221, owe)), -40)

    assert [(hint.bssid, hint.method, hint.ssid) for hint in packet.ssid_hints] == [
        ("aa:bb:cc:dd:ee:ff", "owe_transition", "Cafe-WiFi")
    ]


def _fils_discovery(control: int, ssid_field: bytes) -> bytes:
    header = b"\xd0\x00\x00\x00" + b"\xff" * 6 + BSSID + BSSID + b"\x00\x00"
    return header + b"\x04\x22" + struct.pack("<H", control) + b"\x00" * 10 + ssid_field


def test_fils_discovery_extracts_short_ssid():
    short_ssid = binascii.crc32(b"SixGHz") & 0xffffffff

    packet = WlanFrameParser.parse_80211_frame(
        _fils_discovery(0x0040, struct.pack("<I", short_ssid)), -40,
    )

    assert isinstance(packet, FilsDiscoveryPacket)
    assert packet.short_ssid == short_ssid
    assert packet.ssid is None


def test_fils_discovery_extracts_full_ssid():
    packet = WlanFrameParser.parse_80211_frame(_fils_discovery(6, b"SixGHz!"), -40)

    assert isinstance(packet, FilsDiscoveryPacket)
    assert packet.ssid == "SixGHz!"
    assert packet.short_ssid is None
