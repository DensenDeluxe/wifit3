from types import SimpleNamespace

from textual.widgets import Select

from wifit3.ui.screens.focus_v2.decloak_modal import DecloakModal


def _modal(base: str) -> DecloakModal:
    m = object.__new__(DecloakModal)
    m.base_ssid, m.target = base, SimpleNamespace(bssid="aa:bb:cc:dd:ee:ff")
    return m


def test_initial_text_seeds_from_visible_sibling_base():
    lines = _modal("Home")._initial_text().splitlines()
    assert lines[0] == "$ssid" and "$ssid-Guest" in lines


def test_initial_text_scaffolds_templates_without_a_base():
    assert _modal("")._initial_text().splitlines() == [
        "$ssid", "$ssid-Guest", "$ssid-5G", "$ssid-IoT"]


def _csa_modal(ap_channel: int) -> DecloakModal:
    m = object.__new__(DecloakModal)
    m.target = SimpleNamespace(bssid="aa:bb:cc:dd:ee:ff", channel=ap_channel)
    return m


def test_dest_options_in_band_from_listener_support():
    m = _csa_modal(6)
    listener = SimpleNamespace(supported_channels=[1, 6, 11, 36])
    assert m._dest_options(listener) == [("1", 1), ("11", 11)]
    assert m._dest_default(listener) == 1


def test_dest_options_are_empty_when_listener_is_out_of_band():
    m = _csa_modal(36)
    listener = SimpleNamespace(supported_channels=[1, 6, 11])
    assert m._dest_options(listener) == []
    assert m._dest_default(listener) is Select.BLANK


def test_listener_can_host_requires_spoofable_bssid():
    from wifit3.chips.driver import FakeMacSupport
    spoofable = SimpleNamespace(driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.SPOOFABLE))
    fixed = SimpleNamespace(driver=SimpleNamespace(FAKE_MAC=FakeMacSupport.FIXED_MAC))
    assert DecloakModal._listener_can_host(spoofable) is True
    assert DecloakModal._listener_can_host(fixed) is False
    assert DecloakModal._listener_can_host(None) is False


def test_read_wordlist_prefix_is_bounded_and_preserves_spaces(tmp_path):
    wordlist = tmp_path / "ssids.txt"
    wordlist.write_text("  Office  \nGuest\nThird\n", encoding="utf-8")
    lines, truncated = DecloakModal._read_wordlist_prefix(wordlist, 2)
    assert lines == ["  Office  ", "Guest"]
    assert truncated is True
