from __future__ import annotations

import hashlib
from typing import Iterable, Optional


_BRAINPOOL_P256_PRIME = (
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
)
_BRAINPOOL_P256_A = (
    0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB
)
_BRAINPOOL_P256_B = (
    0x28A22952, 0x21D8B200, 0x90F4A439, 0xDF270A3C,
    0xB8A9A530, 0x5D69853F, 0x07000000, 0x40000000
)
_BRAINPOOL_P256_GX = (
    0xA553E04D, 0x0DB82E1B, 0x0036BFC9, 0x9D831D70,
    0x7843713B, 0x12283C19, 0x07000000, 0x40000000
)
_BRAINPOOL_P256_GY = (
    0x302631FE, 0x3F341361, 0x64AF42C6, 0x7DE8C89B,
    0x5DEB9D29, 0x50EC5548, 0x07000000, 0x40000000
)
_BRAINPOOL_P256_N = (
    0x1B32497F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
)

PRIME_256 = int.from_bytes(b"".join(w.to_bytes(4, "little") for w in _BRAINPOOL_P256_PRIME), "little")
ORDER_256 = int.from_bytes(b"".join(w.to_bytes(4, "little") for w in _BRAINPOOL_P256_N), "little")


def sha256_prf(key: bytes, label: str, seed: bytes, out_len: int) -> bytes:
    output = b""
    counter = 0
    
    while len(output) < out_len:
        data = label.encode() + b"\x00" + seed + counter.to_bytes(4, "big")
        output += hashlib.sha256(key + data).digest()
        counter += 1
    
    return output[:out_len]


def pwd2value(pwd: str, pwd_seed: bytes) -> int:
    prf_output = sha256_prf(pwd_seed, "SAE Hunting and Pecking", b"", 32)
    pwd_value = int.from_bytes(prf_output, "little")
    return pwd_value % (PRIME_256 - 1)


def element2scalar(element: bytes, pwd_value: int) -> int:
    element_int = int.from_bytes(element, "little")
    return (element_int * pwd_value) % ORDER_256


class SAEVerifier:
    def __init__(
        self,
        ap_addr: bytes,
        client_addr: bytes,
        ap_element: bytes,
        client_element: bytes,
        ap_confirm: bytes,
        client_confirm: bytes
    ):
        self.ap_addr = ap_addr
        self.client_addr = client_addr
        self.ap_element = ap_element
        self.client_element = client_element
        self.ap_confirm = ap_confirm
        self.client_confirm = client_confirm
        
        if ap_addr > client_addr:
            self.pwd_seed = ap_addr + client_addr
        else:
            self.pwd_seed = client_addr + ap_addr
    
    def verify(self, password: str) -> bool:
        pwd_value = pwd2value(password, self.pwd_seed)
        ap_scalar = element2scalar(self.ap_element, pwd_value)
        client_scalar = element2scalar(self.client_element, pwd_value)
        shared_secret = (ap_scalar * client_scalar) % ORDER_256
        
        ap_data = b"SAE Confirm" + self.ap_addr + self.client_addr + self.ap_element + self.client_element
        client_data = b"SAE Confirm" + self.client_addr + self.ap_addr + self.client_element + self.ap_element
        
        expected_ap_confirm = hashlib.sha256(shared_secret.to_bytes(32, "little") + ap_data).digest()
        expected_client_confirm = hashlib.sha256(shared_secret.to_bytes(32, "little") + client_data).digest()
        
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
    verifier = SAEVerifier(
        ap_addr, client_addr,
        ap_element, client_element,
        ap_confirm, client_confirm
    )
    
    for password in passwords:
        if verifier.verify(password):
            return password
    
    return None
