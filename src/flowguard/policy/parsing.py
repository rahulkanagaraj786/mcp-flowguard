"""Parse YAML level strings into lattice enums."""

from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.policy.exceptions import PolicyLoadError


def parse_confidentiality(raw: str) -> ConfidentialityLevel:
    key = raw.strip().casefold()
    for level in ConfidentialityLevel:
        if level.name.casefold() == key:
            return level
    raise PolicyLoadError(f"Unknown confidentiality level: {raw!r}")


def parse_integrity(raw: str) -> IntegrityLevel:
    key = raw.strip().casefold()
    for level in IntegrityLevel:
        if level.name.casefold() == key:
            return level
    raise PolicyLoadError(f"Unknown integrity level: {raw!r}")
