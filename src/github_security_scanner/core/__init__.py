"""Core module containing main scanner logic, configuration and data models."""

from .config import Settings, get_settings
from .models import (
    Finding,
    FindingState,
    FindingType,
    Repository,
    ScanMetadata,
    ScanResult,
    Severity,
    StateDetails,
)

# SecurityScanner is imported lazily to avoid circular imports
# Use: from github_security_scanner.core.scanner import SecurityScanner


def __getattr__(name: str):
    """Lazy import for SecurityScanner to avoid circular imports."""
    if name == "SecurityScanner":
        from .scanner import SecurityScanner
        return SecurityScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Finding",
    "FindingState",
    "FindingType",
    "Repository",
    "ScanMetadata",
    "ScanResult",
    "SecurityScanner",
    "Settings",
    "Severity",
    "StateDetails",
    "get_settings",
]

