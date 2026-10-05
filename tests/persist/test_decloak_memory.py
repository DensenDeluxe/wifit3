from pathlib import Path

from wifit3.persist.decloak_memory import DecloakMemory

def test_remember_is_inert_before_load_arms_it(tmp_path):
    DecloakMemory.remember("AA:BB:CC:DD:EE:FF", "Home")
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") is None
    assert not (tmp_path / "decloak.json").exists()


def test_remember_persists_and_reloads_case_insensitively():
    DecloakMemory.load()
    DecloakMemory.remember("AA:BB:CC:DD:EE:FF", "HomeNet")
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") == "HomeNet"

    DecloakMemory._by_bssid = {}
    DecloakMemory.load()
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") == "HomeNet"


def test_remember_ignores_empty_pairs():
    DecloakMemory.load()
    DecloakMemory.remember("", "Home")
    DecloakMemory.remember("aa:bb:cc:dd:ee:ff", "")
    assert DecloakMemory._by_bssid == {}


def test_load_tolerates_corrupt_file(tmp_path):
    (tmp_path / "decloak.json").write_text("{ not json")
    DecloakMemory.load()
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") is None


def test_load_clears_stale_memory_when_file_is_missing():
    DecloakMemory._by_bssid = {"aa:bb:cc:dd:ee:ff": "Stale"}
    DecloakMemory.load()
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") is None


def test_failed_atomic_replace_does_not_poison_memory_or_block_retry(monkeypatch, tmp_path):
    DecloakMemory.load()
    original_replace = Path.replace
    calls = 0

    def fail_once(path, target):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("disk full")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_once)
    DecloakMemory.remember("aa:bb:cc:dd:ee:ff", "Home")
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") is None
    assert not (tmp_path / "decloak.json").exists()

    DecloakMemory.remember("aa:bb:cc:dd:ee:ff", "Home")
    assert DecloakMemory.get("aa:bb:cc:dd:ee:ff") == "Home"
    assert (tmp_path / "decloak.json").exists()


def test_load_ignores_overlong_or_non_string_values(tmp_path):
    (tmp_path / "decloak.json").write_text(
        '{"aa:bb:cc:dd:ee:01": "valid", "aa:bb:cc:dd:ee:02": 3, '
        '"aa:bb:cc:dd:ee:03": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
        encoding="utf-8",
    )
    DecloakMemory.load()
    assert DecloakMemory._by_bssid == {"aa:bb:cc:dd:ee:01": "valid"}


def test_load_ignores_unencodable_surrogate_value(tmp_path):
    (tmp_path / "decloak.json").write_text(
        '{"aa:bb:cc:dd:ee:01": "\\ud800"}', encoding="utf-8",
    )
    DecloakMemory.load()
    assert DecloakMemory._by_bssid == {}
