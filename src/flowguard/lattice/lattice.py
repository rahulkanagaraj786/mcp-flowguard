"""Two-dimensional security lattice (BLP confidentiality × Biba integrity).

`join` / `meet` are the least upper bound and greatest lower bound in the
product of two total orders (confidentiality ↑, integrity with “higher trust”
as larger enum values, combined so join takes min integrity / max conf as in
the spec).

`can_flow` is the *information flow* relation: source may flow to dest iff
source is no more confidential than dest and no less trusted than dest.  This
relation is a partial order on `SecurityLabel` (reflexive, antisymmetric,
transitive), so transitivity of `can_flow` matches the poset structure.
"""

from __future__ import annotations

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


class SecurityLattice:
    """Static lattice operations — reference monitor guardrail."""

    BOTTOM = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    TOP = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)

    @staticmethod
    def join(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Least upper bound (⊔): max(conf), min(integrity)."""
        return SecurityLabel(
            confidentiality=max(a.confidentiality, b.confidentiality),
            integrity=min(a.integrity, b.integrity),
        )

    @staticmethod
    def meet(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Greatest lower bound (⊓): min(conf), max(integrity)."""
        return SecurityLabel(
            confidentiality=min(a.confidentiality, b.confidentiality),
            integrity=max(a.integrity, b.integrity),
        )

    @staticmethod
    def can_flow(source: SecurityLabel, dest: SecurityLabel) -> bool:
        """True iff source ⊑ dest in the product partial order (flow allowed)."""
        return (
            source.confidentiality <= dest.confidentiality
            and source.integrity >= dest.integrity
        )
