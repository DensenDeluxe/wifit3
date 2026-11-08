import hashlib
import struct
from pathlib import Path
from unittest.mock import Mock

from wifit3.campaigns.eviltwin_enterprise import EapServer, EvilTwinEnterpriseCampaign, Method
from wifit3.campaigns.eviltwin_enterprise.eap_server import (
    EAP_FAILURE,
    EAP_MSCHAPv2,
    EAP_PEAP,
    EAP_REQUEST,
    TLS_LENGTH_INCLUDED,
    TLS_MORE_FRAGMENTS,
    TLS_START,
)
from wifit3.dot11.rsn import AKM_802_1X, AKM_FT_PSK, AKM_PSK


def _identity(eid: int, name: bytes = b"user") -> bytes:
    body = bytes([1]) + name
    return struct.pack(">BBH", 2, eid, 4 + len(body)) + body


def test_eap_success_and_failure_have_no_type():
    server = EapServer("lab")
    success = server._eap_success(1)
    failure = server._eap_failure(1)
    assert success == struct.pack(">BBH", 3, 1, 4)
    assert failure == struct.pack(">BBH", 4, 1, 4)


def test_eap_request_carries_type():
    packet = EapServer("lab")._eap_packet(1, 1, 1)
    assert packet == struct.pack(">BBHB", 1, 1, 5, 1)


def test_method_values():
    assert Method.PEAP.value == "PEAP"
    assert Method.TTLS.value == "TTLS"
    assert EapServer("lab", Method.TTLS).method is Method.TTLS


def test_mschapv2_challenge_layout():
    challenge = b"\x10" * 16
    packet = EapServer("lab")._mschapv2_challenge(7, challenge)
    assert packet[0] == EAP_REQUEST
    assert packet[1] == 7
    assert packet[4] == EAP_MSCHAPv2
    ms = packet[5:]
    assert ms[0] == 1
    assert ms[1] == 7
    assert struct.unpack(">H", ms[2:4])[0] == 21
    assert ms[4] == 16
    assert ms[5:21] == challenge
    assert len(ms) == 21


def test_mschapv2_challenge_rejects_other_sizes():
    try:
        EapServer("lab")._mschapv2_challenge(1, b"\x00" * 24)
    except ValueError as exc:
        assert "16 bytes" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_mschapv2_response_capture():
    server = EapServer("lab")
    server._authenticator_challenge = b"AC" + b"\x00" * 14
    peer = b"\x11" * 16
    nt_response = b"\x22" * 24
    raw = bytes([2, 1]) + struct.pack(">H", 58) + bytes([49])
    raw += peer + b"\x00" * 8 + nt_response + b"CORP\\testuser\x00"
    responses = server._handle_mschapv2(raw)
    assert responses[0][0] == EAP_FAILURE
    assert server.captured is not None
    assert server.captured.username == "testuser"
    assert server.captured.response == nt_response.hex()
    expect = hashlib.sha1(peer + server._authenticator_challenge + b"testuser").digest()[:8]
    assert server.captured.challenge == expect.hex()


def test_mschapv2_short_response_is_not_a_capture():
    server = EapServer("lab")
    server._authenticator_challenge = b"\x00" * 16
    responses = server._handle_mschapv2(struct.pack(">BBHB", 2, 1, 10, 49))
    assert server.captured is None
    assert responses[0][0] == EAP_FAILURE


def test_identifier_advances_from_the_response():
    server = EapServer("lab")
    server.process(_identity(5, b"\x00"))
    assert server._id == 6
    server = EapServer("lab")
    server.process(_identity(10, b"\x00"))
    assert server._id == 11


def test_peap_start_is_the_start_flag():
    responses = EapServer("lab").process(_identity(1, b"user"))
    assert len(responses) == 1
    packet = responses[0]
    assert packet[4] == EAP_PEAP
    assert packet[5] == TLS_START
    assert len(packet) == 6


def test_tls_fragments_accumulate_until_the_declared_length():
    server = EapServer("lab")
    server.process(_identity(1, b"user"))
    first = struct.pack(">BBH", 2, 2, 40) + bytes([EAP_PEAP, TLS_LENGTH_INCLUDED | TLS_MORE_FRAGMENTS])
    first += struct.pack(">I", 40) + b"\x01" * 30
    server.process(first)
    assert server._tls_fragment_buffer == b"\x01" * 30
    assert server._tls_more_fragments is True
    assert server._tls_length == 40
    second = struct.pack(">BBH", 2, 3, 16) + bytes([EAP_PEAP, 0]) + b"\x02" * 10
    server.process(second)
    assert server._tls_fragment_buffer == b""
    assert server._tls_more_fragments is False


def test_tls_flight_splits_above_the_chunk():
    server = EapServer("lab")
    server._queue_flight(b"\x16" * 1500)
    assert len(server._tx) == 2
    assert server._tx[0][5] & (TLS_LENGTH_INCLUDED | TLS_MORE_FRAGMENTS) == (
        TLS_LENGTH_INCLUDED | TLS_MORE_FRAGMENTS)
    assert server._tx[1][5] & (TLS_LENGTH_INCLUDED | TLS_MORE_FRAGMENTS) == 0


def test_tls_context_and_cleanup():
    server = EapServer("lab")
    server._init_tls()
    assert server._ssl is not None
    assert server._in_bio is not None
    assert server._out_bio is not None
    path = Path(server._cert_tmpdir.name)
    assert path.exists()
    server.cleanup()
    assert not path.exists()


def test_ttls_avp_round_trip():
    server = EapServer("lab", Method.TTLS)
    wrapped = server._wrap_ttls_avp(b"test")
    assert struct.unpack(">I", wrapped[:4])[0] == 79
    assert server._unwrap_ttls_avp(wrapped) == b"test"


def test_spoofable_is_only_a_spoofable_card():
    from wifit3.chips.driver import FakeMacSupport
    from wifit3.campaigns.eviltwin_enterprise.campaign import spoofable

    class _Driver:
        FAKE_MAC = FakeMacSupport.SPOOFABLE

    class _Iface:
        driver = _Driver()

    assert spoofable(_Iface()) is True
    _Driver.FAKE_MAC = FakeMacSupport.FIXED_MAC
    assert spoofable(_Iface()) is False
    assert spoofable(object()) is False


def test_visible_only_for_enterprise():
    enterprise = Mock(ssid="lab", akm_suites=[AKM_802_1X])
    psk = Mock(ssid="lab", akm_suites=[AKM_PSK])
    ft = Mock(ssid="lab", akm_suites=[AKM_FT_PSK])
    hidden = Mock(ssid=None, akm_suites=[AKM_802_1X], last_beacon_frame=b"beacon")
    assert EvilTwinEnterpriseCampaign.visible(enterprise) is True
    assert EvilTwinEnterpriseCampaign.visible(psk) is False
    assert EvilTwinEnterpriseCampaign.visible(ft) is False
    assert EvilTwinEnterpriseCampaign.visible(hidden) is False
    assert EvilTwinEnterpriseCampaign.ineligible_reason(hidden) == "Hidden SSID"
    assert EvilTwinEnterpriseCampaign.ineligible_reason(
        Mock(ssid="lab", akm_suites=[AKM_PSK], last_beacon_frame=b"beacon")
    ) == "Needs an Enterprise network"
