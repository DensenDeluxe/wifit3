from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from wifit3.crack.wepwolf import crack_wep
from wifit3.models import CaptureType
from wifit3.vault.tools.base import VaultTool, ToolResult


logger = logging.getLogger(__name__)


@dataclass
class WepHashline:
    iv: bytes
    ciphertext: bytes


class WepCrackTool(VaultTool):
    name = "wep-crack"
    display_name = "WEP Crack (WEPWolf)"
    capture_types = {CaptureType.WEP}
    
    def can_crack(self, hashlines: list[WepHashline]) -> bool:
        return bool(hashlines)
    
    def crack(
        self,
        hashlines: list[WepHashline],
        keylen: int = 5,
        wordlist: Optional[Iterable[str]] = None,
        passphrase_list: Optional[Iterable[str]] = None,
        callback: Optional[callable] = None
    ) -> ToolResult:
        if not hashlines:
            return ToolResult(success=False, detail="No hashlines provided")
        
        logger.info(f"Starting WEP crack with {len(hashlines)} samples (keylen={keylen})")
        
        iv_samples = [(hl.iv, hl.ciphertext, None) for hl in hashlines]
        
        key = crack_wep(
            iv_samples=iv_samples,
            keylen=keylen,
            wordlist=list(wordlist) if wordlist else None,
            passphrase_list=list(passphrase_list) if passphrase_list else None
        )
        
        if key:
            logger.info(f"WEP key cracked: {key.hex()}")
            return ToolResult(
                success=True,
                password=key.hex(),
                percent=100,
                detail=f"WEP-{keylen*8} key recovered"
            )
        
        return ToolResult(
            success=False,
            percent=100,
            detail=f"No match in {len(hashlines)} samples"
        )
    
    def priority(self, hashlines: list[WepHashline]) -> int:
        return 80
