"""Global test fixtures."""
import pytest

import wifit3.persist.decloak_memory as decloak_memory
from wifit3.campaigns.campaign import Campaign
from wifit3.persist.config import Config
from wifit3.persist.decloak_memory import DecloakMemory


@pytest.fixture(autouse=True)
def _reset_campaign_active():
    Campaign.active = None   # before test
    yield
    Campaign.active = None   # after test


@pytest.fixture(autouse=True)
def _captures_to_tmp(tmp_path, monkeypatch):
    """Point Config.captures_dir at each test's tmp so nothing writes to ./captures."""
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))


@pytest.fixture(autouse=True)
def _isolate_decloak_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(decloak_memory, "_PATH", tmp_path / "decloak.json")
    monkeypatch.setattr(DecloakMemory, "_by_bssid", {}, raising=False)
    monkeypatch.setattr(DecloakMemory, "_armed", False, raising=False)
