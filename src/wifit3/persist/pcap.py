"""Minimal libpcap writer for raw 802.11 frames.

Produces a standard libpcap-format file (NOT pcapng) with linktype
``LINKTYPE_IEEE802_11`` (105). Suitable for handing to ``hcxpcapngtool``
(which accepts both pcap and pcapng) → ``hashcat -m 22000``.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from typing import Iterable

LINKTYPE_IEEE802_11 = 105
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
SNAPLEN = 65535


def write_pcap(path: Path, records: Iterable[tuple[bytes, float]]) -> int:
    """Write *records*, ``(raw 802.11 frame, capture timestamp)`` pairs, to a
    pcap at *path*. The timestamp is epoch seconds (float).

    Per-frame timing is preserved so the file is forensically accurate AND
    re-extractable by ``hcxpcapngtool``, which pairs EAPOL frames by their
    timestamps (an EAPOL timeout window). Identical stamps would make it
    mis-pair. A timestamp <= 0 (unset) falls back to the current wall-clock
    time so the frame still lands with a sane epoch.

    Returns the number of frames written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    fallback = time.time()
    with path.open("wb") as f:
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION[0], PCAP_VERSION[1],
            0,                      # GMT thiszone
            0,                      # sigfigs
            SNAPLEN,
            LINKTYPE_IEEE802_11,
        ))
        for frame, ts in records:
            if not frame:
                continue
            t = ts if ts and ts > 0 else fallback
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1_000_000)
            length = len(frame)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, length, length))
            f.write(frame)
            count += 1
    return count


def read_pcap(path: Path) -> list[tuple[bytes, float]]:
    """Read a libpcap file written by ``write_pcap`` back into ``(frame, timestamp)``
    pairs. Handles either byte order and drops a truncated trailing record."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    if struct.unpack("<I", data[:4])[0] == PCAP_MAGIC:
        endian = "<"
    elif struct.unpack(">I", data[:4])[0] == PCAP_MAGIC:
        endian = ">"
    else:
        raise ValueError(f"not a libpcap file: bad magic {data[:4].hex()}")
    records: list[tuple[bytes, float]] = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, caplen, _orig = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if offset + caplen > len(data):
            break
        records.append((data[offset:offset + caplen], ts_sec + ts_usec / 1_000_000))
        offset += caplen
    return records
