from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

from platformdirs import user_config_dir

logger = logging.getLogger(__name__)

_PATH = Path(user_config_dir("wifit3", appauthor=False)) / "decloak.json"


def _valid_ssid(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= 32
    except UnicodeError:
        return False


class DecloakMemory:
    _by_bssid: dict[str, str] = {}
    _armed: bool = False
    _lock = threading.RLock()

    @classmethod
    def load(cls) -> None:
        with cls._lock:
            cls._armed = True
            cls._by_bssid = {}
            try:
                data = json.loads(_PATH.read_text("utf-8"))
            except FileNotFoundError:
                return
            except (OSError, ValueError) as exc:
                logger.warning("decloak memory load failed at %s: %s", _PATH, exc)
                return
            if isinstance(data, dict):
                cls._by_bssid = {
                    str(key).lower(): value
                    for key, value in data.items()
                    if key and _valid_ssid(value)
                }

    @classmethod
    def get(cls, bssid: str) -> Optional[str]:
        with cls._lock:
            return cls._by_bssid.get(bssid.lower())

    @classmethod
    def remember(cls, bssid: str, ssid: str) -> None:
        key = bssid.lower()
        if not key or not _valid_ssid(ssid):
            return
        with cls._lock:
            if not cls._armed or cls._by_bssid.get(key) == ssid:
                return
            updated = dict(cls._by_bssid)
            updated[key] = ssid
            temporary_path = None
            try:
                _PATH.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=_PATH.parent,
                    prefix=f".{_PATH.name}.",
                    delete=False,
                ) as temporary:
                    json.dump(updated, temporary, ensure_ascii=False)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary_path = Path(temporary.name)
                temporary_path.replace(_PATH)
            except OSError as exc:
                if temporary_path is not None:
                    try:
                        temporary_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                logger.warning("decloak memory save failed at %s: %s", _PATH, exc)
                return
            cls._by_bssid = updated
