"""WEP cracking tool using WEPWolf algorithms."""

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
    """WEP hashline data."""
    iv: bytes
    ciphertext: bytes


class WepCrackTool(VaultTool):
    """CPU-based WEP cracking using WEPWolf algorithms."""
    
    name = "wep-crack"
    display_name = "WEP Crack (WEPWolf)"
    capture_types = {CaptureType.WEP}
    
    def can_crack(self, hashlines: list[WepHashline]) -> bool:
        """Check if tool can crack these WEP hashlines."""
        return bool(hashlines)
    
    def crack(
        self,
        hashlines: list[WepHashline],
        keylen: int = 5,
        wordlist: Optional[Iterable[str]] = None,
        passphrase_list: Optional[Iterable[str]] = None,
        callback: Optional[callable] = None
    ) -> ToolResult:
        """Crack WEP using WEPWolf statistical attacks.
        
        Args:
            hashlines: List of WEP hashlines (IV + ciphertext)
            keylen: Expected key length (5, 13, or 29)
            wordlist: Optional wordlist for dictionary attack
            passphrase_list: Optional passphrase list for keygen
            callback: Optional progress callback
        
        Returns:
            ToolResult with cracked key or failure
        """
        if not hashlines:
            return ToolResult(success=False, detail="No hashlines provided")
        
        logger.info(f"Starting WEP crack with {len(hashlines)} samples (keylen={keylen})")
        
        # Prepare samples
        iv_samples = [(hl.iv, hl.ciphertext, None) for hl in hashlines]
        
        # Run cracking
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
        """Return tool priority (higher = more preferred)."""
        return 80  # High priority for WEP (faster than WPA)
