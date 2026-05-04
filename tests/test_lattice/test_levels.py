"""Ordering of ConfidentialityLevel and IntegrityLevel."""

from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


def test_confidentiality_total_order() -> None:
    assert ConfidentialityLevel.PUBLIC < ConfidentialityLevel.INTERNAL
    assert ConfidentialityLevel.INTERNAL < ConfidentialityLevel.CONFIDENTIAL
    assert ConfidentialityLevel.CONFIDENTIAL < ConfidentialityLevel.SECRET


def test_integrity_total_order() -> None:
    assert IntegrityLevel.LOW < IntegrityLevel.MEDIUM
    assert IntegrityLevel.MEDIUM < IntegrityLevel.HIGH
