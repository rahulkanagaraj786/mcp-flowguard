"""SecurityLattice join, meet, can_flow."""

from itertools import product

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


def test_join_conf_high_public_low() -> None:
    a = SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)
    b = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    assert SecurityLattice.join(a, b) == SecurityLabel(
        ConfidentialityLevel.CONFIDENTIAL,
        IntegrityLevel.LOW,
    )


def test_secret_cannot_flow_to_public_blp() -> None:
    src = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    dst = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    assert not SecurityLattice.can_flow(src, dst)


def test_low_integrity_cannot_flow_to_high_dest_biba() -> None:
    src = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    dst = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    assert not SecurityLattice.can_flow(src, dst)


def test_meet_dual_of_join_example() -> None:
    a = SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)
    b = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    m = SecurityLattice.meet(a, b)
    assert m == SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)


def test_meet_secret_high_public_low_is_public_high_glb() -> None:
    """GLB: min(conf), max(integrity) — not min on both axes."""
    hi = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    lo = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    assert SecurityLattice.meet(hi, lo) == SecurityLabel(
        ConfidentialityLevel.PUBLIC,
        IntegrityLevel.HIGH,
    )


def test_can_flow_transitivity_example_chain() -> None:
    """If A→B and B→C then A→C (product partial order)."""
    a = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    b = SecurityLabel(ConfidentialityLevel.INTERNAL, IntegrityLevel.MEDIUM)
    c = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)
    assert SecurityLattice.can_flow(a, b)
    assert SecurityLattice.can_flow(b, c)
    assert SecurityLattice.can_flow(a, c)


def test_can_flow_reflexive_all_label_pairs() -> None:
    for c in ConfidentialityLevel:
        for i in IntegrityLevel:
            lbl = SecurityLabel(c, i)
            assert SecurityLattice.can_flow(lbl, lbl)


def test_can_flow_antisymmetry_exhaustive() -> None:
    """If A⊑B and B⊑A then A = B (partial order antisymmetry)."""
    all_labels = [
        SecurityLabel(c, i)
        for c, i in product(ConfidentialityLevel, IntegrityLevel)
    ]
    for a in all_labels:
        for b in all_labels:
            if SecurityLattice.can_flow(a, b) and SecurityLattice.can_flow(b, a):
                assert a == b


def test_can_flow_transitivity_exhaustive() -> None:
    """If A⊑B and B⊑C then A⊑C (partial order transitivity)."""
    all_labels = [
        SecurityLabel(c, i)
        for c, i in product(ConfidentialityLevel, IntegrityLevel)
    ]
    for a in all_labels:
        for b in all_labels:
            for c in all_labels:
                if SecurityLattice.can_flow(a, b) and SecurityLattice.can_flow(b, c):
                    assert SecurityLattice.can_flow(a, c)


def test_top_only_flows_to_top_integrity_when_dest_requires_high() -> None:
    """TOP label requires dest at least SECRET conf and HIGH integ for equality."""
    top = SecurityLattice.TOP
    assert SecurityLattice.can_flow(top, top)


def test_bottom_flow_allowed_to_matching_public_low_dest() -> None:
    bottom = SecurityLattice.BOTTOM
    assert SecurityLattice.can_flow(bottom, bottom)


def test_permissive_dest_internal_medium_blocks_bottom_integrity() -> None:
    bottom = SecurityLattice.BOTTOM
    dest = SecurityLabel(ConfidentialityLevel.INTERNAL, IntegrityLevel.MEDIUM)
    assert not SecurityLattice.can_flow(bottom, dest)
