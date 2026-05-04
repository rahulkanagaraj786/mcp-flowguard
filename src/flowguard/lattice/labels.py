"""Security labels as immutable pairs of lattice levels."""

from __future__ import annotations

from dataclasses import dataclass

from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


@dataclass(frozen=True, order=False)
class SecurityLabel:
    """Bell–LaPadula × Biba style label; no total order — use SecurityLattice for joins/meets."""

    confidentiality: ConfidentialityLevel
    integrity: IntegrityLevel

    def dominates(self, other: SecurityLabel) -> bool:
        return self.confidentiality >= other.confidentiality and self.integrity >= other.integrity

    def __repr__(self) -> str:
        return (
            f"({self.confidentiality.name}, {self.integrity.name})"
        )
