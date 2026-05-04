from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel

class SecurityLattice:

    BOTTOM = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    TOP = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)

    @staticmethod
    def join(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Least upper bound. Used when data from two sources merges.
        Conservative: max confidentiality, min integrity."""
        return SecurityLabel(
            confidentiality=ConfidentialityLevel(max(a.confidentiality, b.confidentiality)),
            integrity=IntegrityLevel(min(a.integrity, b.integrity)),
        )

    @staticmethod
    def meet(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Greatest lower bound."""
        return SecurityLabel(
            confidentiality=ConfidentialityLevel(min(a.confidentiality, b.confidentiality)),
            integrity=IntegrityLevel(max(a.integrity, b.integrity)),
        )

    @staticmethod
    def can_flow(source: SecurityLabel, dest: SecurityLabel) -> bool:
        """Bell-LaPadula + Biba combined flow check.
        BLP: source.conf <= dest.conf  (no write up / no read down for confidentiality)
        Biba: source.integ >= dest.integ (no write down / no read up for integrity)
        """
        return (
            source.confidentiality <= dest.confidentiality
            and source.integrity >= dest.integrity
        )