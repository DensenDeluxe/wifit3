"""Tests for the active-decloak attack: candidate generation and the
frame builder. The driver loop (poll-for-ssid-flip) is covered by the
existing WlanInterface decloak tests once the parser path lights up.
"""
from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from wifit3.campaigns.decloak import (
    SIBLING_SUFFIXES,
    DecloakAttack,
    DecloakCampaign,
    build_candidates,
    expand_candidates,
)
from wifit3.campaigns.csa_decloak import (
    CsaDecloakCampaign, CsaDecloakInput, csa_default_dest, csa_dest_channels,
)
from wifit3.models import AccessPoint
from wifit3.dot11.ie import ds_param_ie, ssid_ie
from wifit3.dot11.mac import mac_header
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.probe import probe_req


def _hidden_beacon(bssid: str = "aa:bb:cc:dd:ee:ff", channel: int = 6) -> bytes:
    b = bytes.fromhex(bssid.replace(":", ""))
    return (mac_header(b"\x80\x00", b, b, b) + struct.pack("<QHH", 0, 100, 0x0011)
            + ssid_ie("") + ds_param_ie(channel))


def test_build_candidates_empty_base_returns_empty():
    assert build_candidates("") == []


def test_build_candidates_dedups_and_orders():
    out = build_candidates("Foo")
    # Empty suffix must be first: covers mesh / same-SSID dual-band case.
    assert out[0] == "Foo"
    # No duplicates.
    assert len(out) == len(set(out))
    # Guest-like variants should appear before the niche -EXT etc.
    guest_idx = out.index("Foo-Guest")
    ext_idx = out.index("Foo-EXT")
    assert guest_idx < ext_idx
    # We get one entry per suffix (after rstrip dedup).
    assert len(out) <= len(SIBLING_SUFFIXES)


def test_build_candidates_strips_trailing_whitespace():
    """' Guest' suffix would produce 'Base Guest', fine. But if base
    already ends in whitespace, we shouldn't propagate that into all
    candidates and shouldn't double up."""
    out = build_candidates("TestSSID 2.4")
    assert "TestSSID 2.4 Guest" in out
    assert "TestSSID 2.4-Guest" in out


def test_build_candidates_skips_suffixes_over_32_utf8_bytes():
    assert build_candidates("ä" * 16) == ["ä" * 16]


def test_decloak_probe_req_parses_back_with_candidate_ssid():
    """Round-trip: feed a frame we built through the same parser the
    receive path uses. Confirms wire format is well-formed AND that the
    SSID we asked for is what an AP would see."""
    mock_array = MagicMock()
    mock_array.access_points = {}
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    attack = DecloakAttack(
        mock_array,
        target,
        base_ssid="Foo",
        source_mac=bytes.fromhex("02deadbeefaa"),
    )

    frame = probe_req(attack.bssid_bytes, attack.source_mac, "Foo-Guest")
    parsed = WlanFrameParser.parse_80211_frame(frame, rssi=-30)

    assert parsed is not None
    assert parsed.type == "probe_req"
    assert parsed.bssid == "aa:bb:cc:dd:ee:ff"
    assert parsed.source == "02:de:ad:be:ef:aa"
    assert parsed.dest == "aa:bb:cc:dd:ee:ff"
    assert parsed.ssid == "Foo-Guest"


def test_decloak_probe_req_handles_empty_ssid_candidate():
    """The '' (mesh/exact-match) suffix yields a candidate equal to the
    base SSID, never an empty SSID IE, since build_candidates filters
    empties. But the builder itself should still accept and round-trip
    a long-SSID candidate."""
    mock_array = MagicMock()
    mock_array.access_points = {}
    target = AccessPoint(bssid="11:22:33:44:55:66", channel=44)
    attack = DecloakAttack(
        mock_array,
        target,
        base_ssid="X" * 32,
        source_mac=bytes.fromhex("020000000001"),
    )
    frame = probe_req(attack.bssid_bytes, attack.source_mac, "X" * 32)
    parsed = WlanFrameParser.parse_80211_frame(frame, rssi=-30)
    assert parsed is not None
    assert parsed.ssid == "X" * 32


def test_decloak_attack_registers_forged_mac():
    """The attack's source MAC must be registered via array.register_forged_mac so the
    EAPOL/handshake/client paths don't treat it as a real STA."""
    mock_array = MagicMock()
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    attack = DecloakAttack(mock_array, target, base_ssid="Foo")
    mock_array.register_forged_mac.assert_called_once_with(attack.source_mac)


def test_decloak_attack_rejects_overlong_override_before_registering_mac():
    mock_array = MagicMock()
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    with pytest.raises(ValueError, match="33 UTF-8 bytes"):
        DecloakAttack(mock_array, target, "", candidates_override=["a" * 33])
    mock_array.register_forged_mac.assert_not_called()


def test_expand_candidates_templates_strips_and_dedupes():
    lines = ["$ssid", "$ssid Guest", "$ssid-5G", "", "Literal", "$ssid"]
    assert expand_candidates(lines, "Home") == ["Home", "Home Guest", "Home-5G", "Literal"]


def test_expand_candidates_literal_lines_without_base():
    assert expand_candidates(["Alpha", "Beta", "Alpha"], "") == ["Alpha", "Beta"]


def test_expand_candidates_preserves_all_legal_spaces_but_drops_empty_lines():
    assert expand_candidates(["  Office  ", "   ", ""], "") == ["  Office  ", "   "]


def test_expand_candidates_rejects_overlong_utf8_and_total_limit():
    with pytest.raises(ValueError, match="33 UTF-8 bytes"):
        expand_candidates(["a" * 33], "")
    with pytest.raises(ValueError, match="At most 2"):
        expand_candidates(["a", "b", "c"], "", max_candidates=2)


def test_decloak_campaign_visible_only_when_hidden():
    hidden = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    named = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, ssid="Home")
    assert DecloakCampaign.visible(hidden) is True
    assert DecloakCampaign.visible(named) is False


async def test_decloak_campaign_unregisters_forged_mac_on_teardown():
    mock_array = MagicMock()
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    camp = DecloakCampaign(mock_array, target, candidates=["Foo"])
    camp._attack = DecloakAttack(mock_array, target, base_ssid="")
    await camp.teardown()
    mock_array.register_forged_mac.assert_called_once_with(camp._attack.source_mac)
    mock_array.unregister_forged_mac.assert_called_once_with(camp._attack.source_mac)


def _iface(channel: int, supported: list[int]):
    iface = AsyncMock()
    iface.current_channel = channel
    iface.supported_channels = supported
    iface.send_no_wait.return_value = True

    async def tune(new_channel, *args, **kwargs):
        iface.current_channel = new_channel
        return True

    iface.set_channel.side_effect = tune
    return iface


def test_csa_dest_channels_in_band_minus_ap():
    assert csa_dest_channels(6, [1, 6, 11, 36, 40]) == [1, 11]
    assert csa_dest_channels(36, [1, 6, 36, 40, 44]) == [40, 44]


def test_csa_default_dest_prefers_classic_decoys():
    assert csa_default_dest(1, [6, 11]) == 6
    assert csa_default_dest(1, [11]) == 11
    assert csa_default_dest(36, [40, 44]) == 40
    assert csa_default_dest(6, []) is None


async def test_csa_decloak_reveals_from_returning_client():
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    target.last_beacon_frame = _hidden_beacon()
    array = MagicMock()
    array.access_points = {"aa:bb:cc:dd:ee:ff": target}

    sender = _iface(6, [1, 6, 11])
    listener = _iface(6, [1, 6, 11])

    async def reveal(*_args, **_kwargs):
        target.ssid = "RevealedNet"
        return True

    sender.send_no_wait.side_effect = reveal

    plan = CsaDecloakInput(sender_iface=sender, listener_iface=listener,
                           dest_channel=1, duration_s=5.0, settle_s=1.0)
    camp = CsaDecloakCampaign(array, target, plan)
    await camp._loop()

    assert camp.revealed == "RevealedNet"
    assert sender.send_no_wait.await_count >= 1
    listener.set_channel.assert_any_await(1)
    array.register_decloak_probe_context.assert_called_once_with(
        target.bssid, listener, 1,
    )
    array.unregister_decloak_probe_context.assert_called_once_with(target.bssid, listener)


async def test_csa_decloak_teardown_restores_each_cards_original_channel():
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    sender = _iface(6, [1, 6, 11])
    listener = _iface(11, [1, 6, 11])
    plan = CsaDecloakInput(sender_iface=sender, listener_iface=listener, dest_channel=1)
    camp = CsaDecloakCampaign(MagicMock(), target, plan)
    sender.current_channel = 1
    listener.current_channel = 1
    await camp.teardown()
    sender.set_channel.assert_awaited_with(6)
    listener.set_channel.assert_awaited_with(11)


async def test_csa_decloak_full_overlap_stands_up_and_tears_down_decoy_ap(monkeypatch):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    target.last_beacon_frame = _hidden_beacon()
    array = MagicMock()
    array.access_points = {"aa:bb:cc:dd:ee:ff": target}
    seen = {}

    class _StubFakeAP:
        def __init__(self, *a, **k):
            seen["built"] = True

        async def start(self):
            seen["started"] = True
            target.ssid = "RevealedNet"

        async def stop(self):
            seen["stopped"] = True

    monkeypatch.setattr("wifit3.campaigns.eviltwin.fake_ap.FakeAP", _StubFakeAP)

    sender = _iface(6, [1, 6, 11])
    listener = _iface(6, [1, 6, 11])
    plan = CsaDecloakInput(sender_iface=sender, listener_iface=listener, dest_channel=1,
                           stand_up_ap=True, duration_s=5.0, settle_s=1.0)
    camp = CsaDecloakCampaign(array, target, plan)
    await camp._loop()

    assert seen.get("started") and seen.get("stopped")
    assert camp.revealed == "RevealedNet"
    array.ignore_stray_beacons.assert_called_once_with("aa:bb:cc:dd:ee:ff", 1)
    array.stop_ignoring_stray_beacons.assert_called_once_with("aa:bb:cc:dd:ee:ff")


async def test_csa_decloak_overlap_lifts_ignore_even_if_decoy_ctor_raises(monkeypatch):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    target.last_beacon_frame = _hidden_beacon()
    array = MagicMock()
    array.access_points = {"aa:bb:cc:dd:ee:ff": target}

    class _BoomFakeAP:
        def __init__(self, *a, **k):
            raise RuntimeError("no spoof")

    monkeypatch.setattr("wifit3.campaigns.eviltwin.fake_ap.FakeAP", _BoomFakeAP)

    sender = _iface(6, [1, 6, 11])
    listener = _iface(6, [1, 6, 11])
    plan = CsaDecloakInput(sender_iface=sender, listener_iface=listener, dest_channel=1,
                           stand_up_ap=True, duration_s=5.0, settle_s=1.0)
    camp = CsaDecloakCampaign(array, target, plan)
    with pytest.raises(RuntimeError):
        await camp._loop()
    array.ignore_stray_beacons.assert_called_once_with("aa:bb:cc:dd:ee:ff", 1)
    array.stop_ignoring_stray_beacons.assert_called_once_with("aa:bb:cc:dd:ee:ff")
    array.unregister_decloak_probe_context.assert_called_once_with(target.bssid, listener)


async def test_decloak_attack_counts_only_successfully_sent_candidates():
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    array = MagicMock()
    array.access_points = {target.bssid: target}
    iface = _iface(6, [6])
    iface.send_no_wait.side_effect = [True, False]
    attack = DecloakAttack(array, target, "", candidates_override=["One", "Two"], iface=iface)

    with pytest.raises(RuntimeError, match="Two"):
        await attack.run(per_candidate_timeout=0)
    assert attack.tried == 1


async def test_decloak_attack_uses_association_oracle_after_silent_probes(monkeypatch):
    target = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", channel=6, encryption="WPA2", rsn_ie=b"\x30\x00",
    )
    array = MagicMock()
    array.access_points = {target.bssid: target}
    iface = _iface(6, [6])
    attempts = []

    class StubAssociation:
        def __init__(self, _iface, _bssid, ssid, _channel, **kwargs):
            attempts.append((ssid, kwargs))
            self.ssid = ssid
            self.associated = False
            self.assoc_status = None

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=1):
            self.associated = self.ssid == "Correct"
            self.assoc_status = 0 if self.associated else 1
            return self.associated

    monkeypatch.setattr("wifit3.campaigns.decloak.Association", StubAssociation)
    attack = DecloakAttack(
        array, target, "", candidates_override=["Wrong", "Correct"], iface=iface,
    )

    assert await attack.run(per_candidate_timeout=0) == "Correct"
    assert attempts[0][0].startswith("wifit3-control-")
    assert [ssid for ssid, _kwargs in attempts[1:]] == ["Wrong", "Correct"]
    assert attempts[0][1]["assoc_trailer_ies"] == b"\x30\x00"
    assert attempts[0][1]["privacy"] is True
    assert attack.association_tried == 2
    array.confirm_decloak.assert_called_once_with(target.bssid, "Correct", "assoc_oracle")


async def test_decloak_association_fallback_is_bounded(monkeypatch):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    array = MagicMock()
    array.access_points = {target.bssid: target}
    iface = _iface(6, [6])

    class RejectingAssociation:
        def __init__(self, *_args, **_kwargs):
            self.associated = False
            self.assoc_status = 1

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=1):
            return False

    monkeypatch.setattr("wifit3.campaigns.decloak.Association", RejectingAssociation)
    attack = DecloakAttack(
        array, target, "", candidates_override=[f"Candidate-{n}" for n in range(40)], iface=iface,
    )

    assert await attack.run(per_candidate_timeout=0) is None
    assert attack.tried == 40
    assert attack.association_tried == 32


async def test_decloak_oracle_aborts_when_ap_accepts_control_ssid(monkeypatch):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    array = MagicMock()
    array.access_points = {target.bssid: target}
    iface = _iface(6, [6])
    attempted = []

    class PermissiveAssociation:
        def __init__(self, _iface, _bssid, ssid, _channel, **_kwargs):
            attempted.append(ssid)
            self.associated = False
            self.assoc_status = None

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=1):
            self.associated = True
            self.assoc_status = 0
            return True

    monkeypatch.setattr("wifit3.campaigns.decloak.Association", PermissiveAssociation)
    attack = DecloakAttack(
        array, target, "", candidates_override=["False-Positive"], iface=iface,
    )

    assert await attack.run(per_candidate_timeout=0) is None
    assert len(attempted) == 1 and attempted[0].startswith("wifit3-control-")
    assert attack.association_tried == 0
    array.confirm_decloak.assert_not_called()


async def test_decloak_oracle_requires_explicit_control_rejection(monkeypatch):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    array = MagicMock()
    array.access_points = {target.bssid: target}
    iface = _iface(6, [6])

    class SilentAssociation:
        def __init__(self, *_args, **_kwargs):
            self.associated = False
            self.assoc_status = None

        def start(self):
            pass

        def stop(self):
            pass

        async def associate(self, attempts=1):
            return False

    monkeypatch.setattr("wifit3.campaigns.decloak.Association", SilentAssociation)
    attack = DecloakAttack(
        array, target, "", candidates_override=["Unproven"], iface=iface,
    )

    assert await attack.run(per_candidate_timeout=0) is None
    assert attack.association_tried == 0
    array.confirm_decloak.assert_not_called()


async def test_csa_decloak_rejects_unsupported_destination_before_transmitting():
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    target.last_beacon_frame = _hidden_beacon()
    sender = _iface(6, [6])
    listener = _iface(6, [6])
    plan = CsaDecloakInput(sender, listener, dest_channel=1)

    with pytest.raises(RuntimeError, match="listener cannot tune"):
        await CsaDecloakCampaign(MagicMock(), target, plan)._loop()
    sender.send_no_wait.assert_not_awaited()


@pytest.mark.parametrize("destination", [6, 36])
async def test_csa_decloak_rejects_same_or_cross_band_destination(destination):
    target = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    target.last_beacon_frame = _hidden_beacon()
    sender = _iface(6, [6])
    listener = _iface(6, [1, 6, 36])
    plan = CsaDecloakInput(sender, listener, dest_channel=destination)
    with pytest.raises(RuntimeError, match="invalid destination"):
        await CsaDecloakCampaign(MagicMock(), target, plan)._loop()
