"""WPA3-SAE cracking tool using dragonforce."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from wifit3.crack.dragonforce import crack_sae as dragonforce_crack
from wifit3.models import CaptureType
from wifit3.vault.tools.base import VaultTool, ToolResult


logger = logging.getLogger(__name__)


@dataclass
class SaeHashline:
    """WPA3-SAE hashline data."""
    ap_addr: bytes
    client_addr: bytes
    ap_element: bytes
    client_element: bytes
    ap_confirm: bytes
    client_confirm: bytes


class SaeCrackTool(VaultTool):
    """CPU-based WPA3-SAE cracking using dragonforce algorithm."""
    
    name = "sae-crack"
    display_name = "SAE Crack (Dragonforce)"
    capture_types = {CaptureType.SAE}
    
    def can_crack(self, hashlines: list[SaeHashline]) -> bool:
        """Check if tool can crack these SAE hashlines."""
        return bool(hashlines)
    
    def crack(
        self,
        hashlines: list[SaeHashline],
        passwords: Iterable[str],
        callback: Optional[callable] = None
    ) -> ToolResult:
        """Crack WPA3-SAE using dragonforce brute-force.
        
        Args:
            hashlines: List of SAE hashlines to crack
            passwords: Iterable of candidate passwords
            callback: Optional progress callback
        
        Returns:
            ToolResult with cracked password or failure
        """
        if not hashlines:
            return ToolResult(success=False, detail="No hashlines provided")
        
        # Use first hashline (SAE typically one attempt)
        hl = hashlines[0]
        
        passwords_list = list(passwords)
        total = len(passwords_list)
        
        logger.info(f"Starting SAE crack with {total} passwords")
        
        for i, password in enumerate(passwords_list):
            try:
                if dragonforce_crack(
                    ap_addr=hl.ap_addr,
                    client_addr=hl.client_addr,
                    ap_element=hl.ap_element,
                    client_element=hl.client_element,
                    ap_confirm=hl.ap_confirm,
                    client_confirm=hl.client_confirm,
                    passwords=[password]
                ):
                    percent = int((i + 1) / total * 100)
                    return ToolResult(
                        success=True,
                        password=password,
                        percent=percent,
                        detail=f"Cracked after {i + 1}/{total} passwords"
                    )
            except Exception as e:
                logger.debug(f"Error testing password: {e}")
                continue
            
            # Progress update
            if callback and (i + 1) % 1000 == 0:
                try:
                    callback(int((i + 1) / total * 100), f"Tested {i + 1}/{total}")
                except Exception:
                    pass
        
        return ToolResult(
            success=False,
            percent=100,
            detail=f"No match in {total} passwords"
        )
    
    def priority(self, hashlines: list[SaeHashline]) -> int:
        """Return tool priority for these hashlines (higher = more preferred)."""
        return 50  # Medium priority, below hashcat
