from __future__ import annotations

import binascii
import hashlib
from typing import Optional


COMMON_KEYS: list[str] = [
    "1234567890",
    "12345",
    "1029384756102",
    "87654321PHARM",
    "498753686e",
    "d89963dcae",
    "1f1f1f1f1f",
    "1111122222",
    "1471471471",
    "qwert",
    "0000000000",
    "ffffffffff",
]

SNAP_KNOWN = bytes([0xAA, 0xAA, 0x03, 0x00])

LCG_MUL = 0x000343FD
LCG_ADD = 0x00269EC3

KOREK_WEIGHTS = [13, 4]


def rc4_ksa(key: bytes) -> list[int]:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list[int], length: int) -> bytes:
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    S = rc4_ksa(key)
    keystream = rc4_prga(S, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))


def crc32_cisco(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def verify_wep_key(key: bytes, iv: bytes, ciphertext: bytes) -> bool:
    if len(ciphertext) < 8:
        return False
    
    rc4_key = iv + key
    plaintext = rc4_decrypt(rc4_key, ciphertext)
    
    data = plaintext[:-4]
    icv_received = int.from_bytes(plaintext[-4:], "little")
    icv_computed = crc32_cisco(data)
    
    return icv_computed == icv_received


def neesus_lcg(passphrase: bytes) -> list[bytes]:
    seed = 0
    for i, c in enumerate(passphrase):
        seed ^= c << ((i & 3) * 8)
    
    keys = []
    rng = seed
    for _ in range(4):
        key_bytes = []
        for _ in range(5):
            rng = (rng * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
            key_bytes.append(rng & 0xFF)
        keys.append(bytes(key_bytes))
    
    return keys


def md5_104(passphrase: bytes) -> bytes:
    return hashlib.md5(passphrase).digest()[:13]


class IvSample:
    __slots__ = ("iv", "keystream")
    
    def __init__(self, iv: bytes, keystream: bytes):
        self.iv = iv
        self.keystream = keystream


def fms_recover(samples: list[IvSample], keylen: int) -> Optional[bytes]:
    if not samples:
        return None
    
    secret = bytearray(keylen)
    
    for b in range(keylen):
        target_iv0 = (3 + b) % 256
        votes = [0] * 256
        
        for sample in samples:
            if sample.iv[0] != target_iv0 or sample.iv[1] != 0xFF:
                continue
            if len(sample.keystream) < 1:
                continue
            
            state = list(range(256))
            j = 0
            key_idx = 3 + b
            
            for i in range(key_idx):
                if i < 3:
                    k = sample.iv[i]
                else:
                    k = secret[i - 3]
                j = (j + state[i] + k) % 256
                state[i], state[j] = state[j], state[i]
            
            z = sample.keystream[0]
            s_inv = state.index(z) if z in state else 0
            prediction = (s_inv - state[key_idx] - j) % 256
            votes[prediction] += 1
        
        secret[b] = max(range(256), key=lambda x: votes[x])
    
    return bytes(secret)


def ptw_recover(samples: list[IvSample], keylen: int) -> Optional[bytes]:
    if not samples:
        return None
    
    table = [[0] * 256 for _ in range(keylen)]
    W_KLEIN, W_MP = KOREK_WEIGHTS
    
    seen_ivs = set()
    for sample in samples:
        iv = sample.iv
        if iv in seen_ivs or len(sample.keystream) < keylen + 2:
            continue
        seen_ivs.add(iv)
        
        S = rc4_ksa(iv)
        
        for pos in range(keylen):
            idx = 3 + pos
            if idx >= len(sample.keystream):
                break
            
            keystream_byte = sample.keystream[idx]
            s_inv = S.index(keystream_byte) if keystream_byte in S else 0
            
            j = 0
            for step in range(idx + 1):
                j = (j + S[step] + (iv[step % 3] if step < 3 else 0)) % 256
            
            sigma = (s_inv - idx - j) % 256
            table[pos][sigma] += W_KLEIN
            
            if pos > 0:
                table[pos][sigma] += W_MP
    
    sigma_candidates = [max(range(256), key=lambda x: table[pos][x]) 
                       for pos in range(keylen)]
    
    key = bytearray(keylen)
    key[0] = sigma_candidates[0]
    for pos in range(1, keylen):
        key[pos] = (sigma_candidates[pos] - sigma_candidates[pos - 1]) % 256
    
    return bytes(key)


def crack_wep(
    iv_samples: list[tuple[bytes, bytes, Optional[bytes]]],
    keylen: int = 5,
    wordlist: Optional[list[str]] = None,
    passphrase_list: Optional[list[str]] = None
) -> Optional[bytes]:
    if not iv_samples:
        return None
    
    all_words = COMMON_KEYS.copy()
    if wordlist:
        all_words.extend(wordlist)
    
    for word in all_words:
        if len(word) == keylen:
            key = word.encode("ascii")
            if _verify_key(key, iv_samples):
                return key
        
        try:
            hex_key = bytes.fromhex(word)
            if len(hex_key) == keylen:
                if _verify_key(hex_key, iv_samples):
                    return hex_key
        except ValueError:
            pass
    
    if passphrase_list:
        for passphrase in passphrase_list:
            pw = passphrase.encode("ascii")
            
            if keylen == 5:
                for key in neesus_lcg(pw):
                    if _verify_key(key, iv_samples):
                        return key
            
            if keylen == 13:
                key = md5_104(pw)
                if _verify_key(key, iv_samples):
                    return key
    
    samples = []
    for iv, ciphertext, _ in iv_samples:
        if len(ciphertext) >= len(SNAP_KNOWN):
            keystream = bytes(c ^ s for c, s in zip(ciphertext[:len(SNAP_KNOWN)], SNAP_KNOWN))
            samples.append(IvSample(iv, keystream))
    
    if not samples:
        return None
    
    key = fms_recover(samples, keylen)
    if key and _verify_key(key, iv_samples):
        return key
    
    key = ptw_recover(samples, keylen)
    if key and _verify_key(key, iv_samples):
        return key
    
    return None


def _verify_key(key: bytes, iv_samples: list[tuple[bytes, bytes, Optional[bytes]]]) -> bool:
    verified = 0
    for iv, ciphertext, _ in iv_samples[:20]:
        if verify_wep_key(key, iv, ciphertext):
            verified += 1
            if verified >= 2:
                return True
    return False
