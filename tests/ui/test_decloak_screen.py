from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from wifit3.campaigns.decloak import DecloakCampaign
from wifit3.campaigns.csa_decloak import CsaDecloakCampaign, CsaDecloakInput
from wifit3.models import AccessPoint
from wifit3.persist.decloak_memory import DecloakMemory
from wifit3.ui.screens.focus_v2.screen import FocusViewV2
from wifit3.ui.screens.scanner import ScannerView


def _finish(camp) -> list:
    logs: list = []
    screen = object.__new__(FocusViewV2)
    screen._log = logs.append
    FocusViewV2._finish_decloak(screen, camp)
    return logs


def _camp(**over):
    base = dict(revealed=None, stopped=False, iface=object(),
                ap=SimpleNamespace(channel=6), csa=None, tried=12, error=None)
    base.update(over)
    return SimpleNamespace(**base)


def test_finish_decloak_names_dead_radio_not_a_no_match():
    line = _finish(_camp(iface=None, tried=0))[-1]
    assert "no card could reach CH 6" in line
    assert "no candidate matched" not in line


def test_finish_decloak_probe_miss_reports_tried_count():
    line = _finish(_camp(iface=object(), tried=12))[-1]
    assert "no candidate matched" in line and "12" in line


def test_finish_decloak_csa_miss_reports_no_client():
    line = _finish(_camp(csa=SimpleNamespace(), tried=0))[-1]
    assert "no client returned on the destination channel" in line


def test_finish_decloak_silent_on_reveal():
    assert _finish(_camp(revealed="HomeNet")) == []


def test_finish_decloak_stopped_is_not_a_dead_radio():
    line = _finish(_camp(stopped=True, iface=None))[-1]
    assert "stopped" in line.lower()


def test_finish_decloak_reports_runtime_error_even_after_stop():
    line = _finish(_camp(stopped=True, error=RuntimeError("tune failed")))[-1]
    assert "Decloak failed" in line and "tune failed" in line


@pytest.fixture
def _remembered(monkeypatch):
    monkeypatch.setattr(DecloakMemory, "_by_bssid", {"aa:bb:cc:dd:ee:ff": "HomeNet"}, raising=False)
    monkeypatch.setattr(DecloakMemory, "_armed", True, raising=False)


def _screen(current=None, tried=()):
    s = object.__new__(FocusViewV2)
    s._controls = SimpleNamespace(current=current, start=MagicMock(return_value=object()))
    s._decloak_confirm_tried = set(tried)
    s._log = MagicMock()
    s.refresh_buttons = MagicMock()
    return s


def test_auto_confirm_eligible_for_remembered_hidden_idle(_remembered):
    s = _screen()
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    assert FocusViewV2._should_auto_confirm_decloak(s, ap) is True


def test_auto_confirm_skipped_when_not_remembered(_remembered):
    s = _screen()
    ap = AccessPoint(bssid="11:22:33:44:55:66", channel=6)
    assert FocusViewV2._should_auto_confirm_decloak(s, ap) is False


def test_auto_confirm_skipped_when_already_tried_or_busy(_remembered):
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    assert FocusViewV2._should_auto_confirm_decloak(
        _screen(tried={"aa:bb:cc:dd:ee:ff"}), ap) is False
    assert FocusViewV2._should_auto_confirm_decloak(
        _screen(current=SimpleNamespace(key="wps")), ap) is False


def test_auto_confirm_skipped_when_not_hidden(_remembered):
    s = _screen()
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, ssid="HomeNet")
    assert FocusViewV2._should_auto_confirm_decloak(s, ap) is False


def test_start_decloak_confirm_logs_and_probes_stored_name(_remembered, monkeypatch):
    s = _screen()
    monkeypatch.setattr(FocusViewV2, "app", property(lambda self: SimpleNamespace(array=object())))
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    FocusViewV2._start_decloak_confirm(s, ap)

    assert "aa:bb:cc:dd:ee:ff" in s._decloak_confirm_tried
    logged = s._log.call_args[0][0]
    assert "Decloaking" in logged and "HomeNet" in logged
    _, kwargs = s._controls.start.call_args
    assert kwargs["candidates"] == ["HomeNet"]
    assert s._controls.start.call_args[0][0] is DecloakCampaign


def test_start_decloak_confirm_does_not_mark_a_busy_attempt(_remembered, monkeypatch):
    s = _screen()
    s._controls.start.return_value = None
    monkeypatch.setattr(FocusViewV2, "app", property(lambda self: SimpleNamespace(array=object())))
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    FocusViewV2._start_decloak_confirm(s, ap)
    assert s._decloak_confirm_tried == set()
    s._log.assert_not_called()


def test_csa_modal_result_starts_separate_csa_campaign(monkeypatch):
    s = object.__new__(FocusViewV2)
    s._target_ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)
    s._controls = SimpleNamespace(start=MagicMock(return_value=object()))
    s._log = MagicMock()
    s.refresh_buttons = MagicMock()
    array = SimpleNamespace()
    monkeypatch.setattr(FocusViewV2, "app", property(lambda self: SimpleNamespace(array=array)))
    iface = SimpleNamespace()
    request = CsaDecloakInput(iface, iface, dest_channel=1)

    FocusViewV2._on_decloak_input(s, request)

    assert s._controls.start.call_args[0][0] is CsaDecloakCampaign


async def test_scanner_decloak_handoff_stops_hopping_before_focus(monkeypatch):
    s = object.__new__(ScannerView)
    array = SimpleNamespace(stop_hopping=AsyncMock())
    focus = SimpleNamespace(queue_decloak=MagicMock())
    app = SimpleNamespace(
        array=array,
        target_ap=None,
        get_screen=MagicMock(return_value=focus),
        push_screen=MagicMock(),
    )
    monkeypatch.setattr(ScannerView, "app", property(lambda self: app))
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6)

    await ScannerView._open_decloak_in_focus(s, ap, ["Candidate"])

    array.stop_hopping.assert_awaited_once()
    assert app.target_ap is ap
    focus.queue_decloak.assert_called_once_with(["Candidate"])
    app.push_screen.assert_called_once_with("focus")
