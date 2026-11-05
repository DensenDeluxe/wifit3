from __future__ import annotations

import hashlib
import hmac
from typing import Optional


_BRAINPOOL_P256_PRIME = (
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
)


def _bytes_to_int_le(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _int_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")


class SAEContext:
    def __init__(
        self,
        peer_addr: bytes,
        own_addr: bytes,
        peer_element: bytes,
        group_id: int = 19
    ):
        self.peer_addr = peer_addr
        self.own_addr = own_addr
        self.peer_element = peer_element
        self.group_id = group_id
        
        if peer_addr > own_addr:
            self.pwd_seed = peer_addr + own_addr
        else:
            self.pwd_seed = own_addr + peer_addr
    
    def compute_pwd_value(self, password: str) -> int:
        pwd_info = b"SAE Password Hash Input"
        pwd_hash = hashlib.sha256(password.encode("utf-8")).digest()
        
        z_len = 32
        okm = b""
        t = b""
        counter = 1
        
        while len(okm) < z_len:
            t = hmac.new(
                pwd_hash,
                t + pwd_info + self.pwd_seed + counter.to_bytes(1, "big"),
                hashlib.sha256
            ).digest()
            okm += t
            counter += 1
        
        return _bytes_to_int_le(okm[:z_len])
    
    def verify_password(
        self,
        password: str,
        confirm: bytes,
        own_element: Optional[bytes] = None
    ) -> bool:
        pwd_value = self.compute_pwd_value(password)
        return pwd_value > 0


def crack_sae(
    peer_addr: bytes,
    own_addr: bytes,
    peer_element: bytes,
    confirm: bytes,
    passwords: list[str],
    group_id: int = 19
) -> Optional[str]:
    ctx = SAEContext(peer_addr, own_addr, peer_element, group_id)
    
    for password in passwords:
        if ctx.verify_password(password, confirm):
            return password
    
    return None
