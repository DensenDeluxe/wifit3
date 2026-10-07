"""RTL8922AU active-monitor tests."""
from unittest.mock import MagicMock

import wifit3.chips.rtl8922au.driver as driver_module
from wifit3.chips.rtl8922au.constants import RTW89_BSSID_MATCH_ALL
from wifit3.chips.rtl8922au.driver import RTL8922AUDriver


async def test_active_monitor_keeps_bssid_cam_match_all(monkeypatch):
    driver = RTL8922AUDriver()
    driver.transport = MagicMock()
    driver._h2c_ep = 0x07
    programmed = {}

    def record_addr_cam(_transport, _endpoint, **fields):
        programmed.update(fields)

    monkeypatch.setattr(driver_module.firmware, "h2c_addr_cam", record_addr_cam)
    mac = bytes.fromhex("020000000001")
    bssid = bytes.fromhex("5414f3bbc48e")

    assert await driver.enter_active_monitor(mac, bssid) == mac
    assert programmed["sma"] == mac
    assert programmed["tma"] == bssid
    assert programmed["bssid"] == bssid
    assert programmed["bssid_mask"] == RTW89_BSSID_MATCH_ALL
