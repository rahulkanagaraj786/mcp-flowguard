"""SecurityLabel behavior."""

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


def test_dominates_same_or_lower_in_both_dimensions() -> None:
    hi = SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)
    lo = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    assert hi.dominates(lo)
    assert not lo.dominates(hi)


def test_frozen_hashable() -> None:
    a = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    b = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    assert hash(a) == hash(b)
    assert {a, b} == {a}


def test_repr_style() -> None:
    s = SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)
    assert repr(s) == "(CONFIDENTIAL, HIGH)"
