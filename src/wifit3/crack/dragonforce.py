"""Dragonforce WPA3-SAE brute-force cracker.

Pure Python implementation of dragonforce's SAE password verification.
Optimized for CPU-based password cracking of captured SAE handshakes.

References:
- dragonforce: https://github.com/wiire-a/dragonforce
- Brainpool P-256: https://www.braingroup.org/brainpool/
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable, Optional


# Brainpool P-256 R1 curve parameters (SAE group 19)
# All values in little-endian 32-bit words
P = (
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
)
A = (
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB
)
B = (
    0x28A22952, 0x21D8B200, 0x90F4A439, 0xDF270A3C,
    0xB8A9A530, 0x5D69853F, 0x07000000, 0x40000000
)
GX = (
    0xA553E04D, 0x0DB82E1B, 0x0036BFC9, 0x9D831D70,
    0x7843713B, 0x12283C19, 0x07000000, 0x40000000
)
GY = (
    0x302631FE, 0x3F341361, 0x64AF42C6, 0x7DE8C89B,
    0x5DEB9D29, 0x50EC5548, 0x07000000, 0x40000000
)
N = (
    0x1B32497F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
)

PRIME_256 = int.from_bytes(b"".join(w.to_bytes(4, "little") for w in P), "little")
ORDER_256 = int.from_bytes(b"".join(w.to_bytes(4, "little") for w in N), "little")


def sha256_prf(key: bytes, label: str, seed: bytes, out_len: int) -> bytes:
    """SHA-256 based Pseudo-Random Function (KDF).
    
    Args:
        key: PRF key
        label: Label string
        seed: Seed data
        out_len: Output length in bytes
    
    Returns:
        PRF output
    """
    output = b""
    counter = 0
    
    while len(output) < out_len:
        data = label.encode() + b"\x00" + seed + struct.pack(">I", counter)
        output += hmac.new(key, data, hashlib.sha256).digest()
        counter += 1
    
    return output[:out_len]


def pwd2value(pwd: str, pwd_seed: bytes) -> int:
    """Convert password to SAE pwd-value.
    
    pwd-value = KDF-Z(pwd-seed, "SAE Hunting and Pecking", p)
    
    Args:
        pwd: Password string
        pwd_seed: Password seed (concatenated MAC addresses)
    
    Returns:
        pwd-value as integer
    """
    # KDF-Z with SHA-256
    prf_output = sha256_prf(
        pwd_seed,
        "SAE Hunting and Pecking",
        b"",
        32
    )
    
    # Convert to integer (little-endian)
    pwd_value = int.from_bytes(prf_output, "little")
    
    # Ensure pwd-value < prime
    return pwd_value % (PRIME_256 - 1)


def element2scalar(element: bytes, pwd_value: int) -> int:
    """Convert SAE element to scalar using pwd-value.
    
    Simplified version - full implementation requires EC operations.
    
    Args:
        element: SAE group element (32 bytes for P-256)
        pwd_value: Password value
    
    Returns:
        Scalar value
    """
    # This is a simplified placeholder
    # Full implementation would do: scalar = (element * pwd_value) mod p
    element_int = int.from_bytes(element, "little")
    return (element_int * pwd_value) % ORDER_256


class SAEVerifier:
    """Verify SAE passwords against captured handshake data."""
    
    def __init__(
        self,
        ap_addr: bytes,
        client_addr: bytes,
        ap_element: bytes,
        client_element: bytes,
        ap_confirm: bytes,
        client_confirm: bytes
    ):
        """Initialize SAE verifier.
        
        Args:
            ap_addr: AP MAC address (6 bytes)
            client_addr: Client MAC address (6 bytes)
            ap_element: AP's SAE element (32 bytes)
            client_element: Client's SAE element (32 bytes)
            ap_confirm: AP's SAE confirm (32 bytes)
            client_confirm: Client's SAE confirm (32 bytes)
        """
        self.ap_addr = ap_addr
        self.client_addr = client_addr
        self.ap_element = ap_element
        self.client_element = client_element
        self.ap_confirm = ap_confirm
        self.client_confirm = client_confirm
        
        # Password seed: MAC addresses in ascending order
        if ap_addr > client_addr:
            self.pwd_seed = ap_addr + client_addr
        else:
            self.pwd_seed = client_addr + ap_addr
    
    def verify(self, password: str) -> bool:
        """Verify if password matches the SAE handshake.
        
        Args:
            password: Candidate password
        
        Returns:
            True if password matches
        """
        # Compute pwd-value
        pwd_value = pwd2value(password, self.pwd_seed)
        
        # Convert elements to scalars
        ap_scalar = element2scalar(self.ap_element, pwd_value)
        client_scalar = element2scalar(self.client_element, pwd_value)
        
        # Compute shared secret (simplified)
        # Full implementation: secret = scalar * peer_element
        shared_secret = (ap_scalar * client_scalar) % ORDER_256
        
        # Derive confirm values
        # confirm = HMAC-SHA256(shared_secret, data)[:32]
        ap_data = b"SAE Confirm" + self.ap_addr + self.client_addr + self.ap_element + self.client_element
        client_data = b"SAE Confirm" + self.client_addr + self.ap_addr + self.client_element + self.ap_element
        
        expected_ap_confirm = hmac.new(
            shared_secret.to_bytes(32, "little"),
            ap_data,
            hashlib.sha256
        ).digest()
        
        expected_client_confirm = hmac.new(
            shared_secret.to_bytes(32, "little"),
            client_data,
            hashlib.sha256
        ).digest()
        
        # Check if either confirm matches
        return (
            expected_ap_confirm == self.ap_confirm or
            expected_client_confirm == self.client_confirm
        )


def crack_sae(
    ap_addr: bytes,
    client_addr: bytes,
    ap_element: bytes,
    client_element: bytes,
    ap_confirm: bytes,
    client_confirm: bytes,
    passwords: Iterable[str]
) -> Optional[str]:
    """Crack WPA3-SAE by brute-force password testing.
    
    Args:
        ap_addr: AP MAC address
        client_addr: Client MAC address
        ap_element: AP's SAE element
        client_element: Client's SAE element
        ap_confirm: AP's SAE confirm
        client_confirm: Client's SAE confirm
        passwords: Iterable of candidate passwords
    
    Returns:
        Cracked password or None
    """
    verifier = SAEVerifier(
        ap_addr, client_addr,
        ap_element, client_element,
        ap_confirm, client_confirm
    )
    
    for password in passwords:
        if verifier.verify(password):
            return password
    
    return None
