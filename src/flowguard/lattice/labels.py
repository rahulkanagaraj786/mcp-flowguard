from dataclasses import dataclass
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel

@dataclass(frozen=True, order=False)
class SecurityLabel:
    confidentiality: ConfidentialityLevel
    integrity: IntegrityLevel

    def dominates(self, other: "SecurityLabel") -> bool:
        """True if self >= other in BOTH dimensions."""
        return (
            self.confidentiality >= other.confidentiality
            and self.integrity >= other.integrity
        )

    def __repr__(self) -> str:
        return f"({self.confidentiality.name}, {self.integrity.name})"