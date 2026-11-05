from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from wifit3.campaigns.campaign import Campaign


logger = logging.getLogger(__name__)


class DragonslayerAttack(Enum):
    REFLECTION = auto()
    INVALID_CURVE = auto()
    INVALID_CURVE_V2 = auto()
    ZERO_SCALAR = auto()


@dataclass
class DragonslayerResult:
    success: bool = False
    password: Optional[str] = None
    attack_type: Optional[DragonslayerAttack] = None
    message: str = ""


class DragonslayerCampaign(Campaign):
    key = "dragonslayer"
    idle_label = "Dragonslayer"
    run_label = "Stop Dragonslayer"
    
    def __init__(
        self,
        ap,
        array,
        attack_type: DragonslayerAttack = DragonslayerAttack.REFLECTION,
        channel: int = 1
    ):
        super().__init__(ap, array)
        self.attack_type = attack_type
        self.channel = channel
        self.result: Optional[DragonslayerResult] = None
    
    async def _loop(self):
        logger.info(
            f"Starting Dragonslayer {self.attack_type.name} attack "
            f"against {self.ap.ssid} ({self.ap.bssid.hex()})"
        )
        
        try:
            iface = self.iface
            await iface.set_channel(self.channel)
            
            if self.attack_type == DragonslayerAttack.REFLECTION:
                result = await self._reflection_attack()
            elif self.attack_type == DragonslayerAttack.INVALID_CURVE:
                result = await self._invalid_curve_attack()
            elif self.attack_type == DragonslayerAttack.ZERO_SCALAR:
                result = await self._zero_scalar_attack()
            else:
                result = DragonslayerResult(
                    success=False,
                    message=f"Unsupported attack type: {self.attack_type}"
                )
            
            self.result = result
            
            if result.success:
                logger.info(f"Dragonslayer attack successful: {result.message}")
            else:
                logger.debug(f"Dragonslayer attack failed: {result.message}")
            
        except Exception as e:
            logger.error(f"Dragonslayer attack error: {e}")
            self.result = DragonslayerResult(success=False, message=str(e))
    
    async def _reflection_attack(self) -> DragonslayerResult:
        return DragonslayerResult(
            success=False,
            attack_type=DragonslayerAttack.REFLECTION,
            message="Reflection attack requires dragonslayer wpa_supplicant"
        )
    
    async def _invalid_curve_attack(self) -> DragonslayerResult:
        return DragonslayerResult(
            success=False,
            attack_type=DragonslayerAttack.INVALID_CURVE,
            message="Invalid curve attack requires dragonslayer wpa_supplicant"
        )
    
    async def _zero_scalar_attack(self) -> DragonslayerResult:
        return DragonslayerResult(
            success=False,
            attack_type=DragonslayerAttack.ZERO_SCALAR,
            message="Zero-scalar attack requires dragonslayer wpa_supplicant"
        )
