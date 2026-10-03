"""Known-answer tests for the PixieDust weak-PRNG ports (campaigns/wps/pixie_prng.py).

Vectors in data/pixie_prng_vectors.json are the verbatim output of pixiewps 1.4.2's own PRNG
routines (see the fixture's _provenance), so these assert the Python port is byte-for-byte the
reference. The RTL819x generator is additionally pinned to the canonical glibc srandom(1) sequence.
"""

import json
from pathlib import Path

import pytest

from wifit3.campaigns.wps import pixie_prng as P

_VEC = json.loads((Path(__file__).parent / "data" / "pixie_prng_vectors.json").read_text())


@pytest.mark.parametrize("seed, want", _VEC["rtl_nonce_fill"].items())
def test_rtl_nonce_fill_matches_reference(seed, want):
    assert P.rtl_nonce_fill(int(seed)).hex() == want


@pytest.mark.parametrize("seed, want", _VEC["glibc_fast_nonce"].items())
def test_glibc_fast_nonce_matches_reference(seed, want):
    assert P.glibc_fast_nonce(int(seed)).hex() == want


@pytest.mark.parametrize("seed, want", _VEC["glibc_fast_seed"].items())
def test_glibc_fast_seed_matches_reference(seed, want):
    assert P.glibc_fast_seed(int(seed)) == want


def test_rtl_reproduces_canonical_glibc_srandom1():
    # glibc `srandom(1); random()` → 1804289383, 846930886, 1681692777, 1714636915.
    import struct
    words = struct.unpack(">IIII", P.rtl_nonce_fill(1))
    assert words == (1804289383, 846930886, 1681692777, 1714636915)


@pytest.mark.parametrize("sreg, want", _VEC["ralink_forward"].items())
def test_ralink_forward_matches_reference(sreg, want):
    assert P.ralink_forward_stream(int(sreg), 48).hex() == want


@pytest.mark.parametrize("sreg, rec", _VEC["ralink_recover"].items())
def test_ralink_recover_matches_reference(sreg, rec):
    forward = bytes.fromhex(_VEC["ralink_forward"][sreg])
    e_nonce = forward[32:48]
    out = P.ralink_recover(e_nonce)
    assert out is not None
    es1, es2 = out
    assert es1.hex() == rec["es1"]
    assert es2.hex() == rec["es2"]
    # The two secrets precede the nonce in the forward stream.
    assert es1 == forward[0:16]
    assert es2 == forward[16:32]


def test_ralink_recover_rejects_impossible_nonce():
    # Corrupting an early byte of a genuine LFSR run breaks the forward re-check (the restored
    # 32-bit state is fixed by the final bytes, so byte 0 no longer regenerates).
    valid = P.ralink_forward_stream(0xCAFEBABE, 48)[32:48]
    corrupt = bytes([valid[0] ^ 0xFF]) + valid[1:]
    assert P.ralink_recover(corrupt) is None


def test_rtl_find_nonce_seed_roundtrips_in_window():
    seed = 1700000000
    nonce = P.glibc_fast_nonce(seed)
    assert P.rtl_find_nonce_seed(nonce, seed + 5, seed - 5) == seed


def test_rtl_find_nonce_seed_absent_outside_window():
    seed = 1700000000
    nonce = P.glibc_fast_nonce(seed)
    assert P.rtl_find_nonce_seed(nonce, seed + 100, seed + 50) is None


@pytest.mark.parametrize("seed, want", _VEC["ecos_rand_simple_stream"].items())
def test_ecos_rand_simple_stream_matches_reference(seed, want):
    s = int(seed)
    out = bytearray()
    for _ in range(48):
        v, s = P.ecos_rand_simple(s)
        out.append(v & 0xFF)
    assert out.hex() == want


def test_ecos_simple_model_recover_roundtrip():
    seed = (0x05 << 25) | 137          # small low 25 bits so the sweep finishes fast
    nonce, es1, es2 = P.ecos_simple_model(seed)
    assert P.ecos_simple_recover(nonce, max_counter=1000) == (es1, es2)
