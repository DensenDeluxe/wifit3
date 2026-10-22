"""Security advisories derived from an access point's advertised configuration."""
from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityWarning:
    """One advisory about an AP: a stable ``code``, a ``severity``, and a human message."""
    code: str
    severity: Severity
    message: str
