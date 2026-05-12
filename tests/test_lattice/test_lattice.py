from flowguard.lattice.lattice import SecurityLattice
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel as C, IntegrityLevel as I

def test_can_flow_public_low_to_public_low():
    assert SecurityLattice.can_flow(
        SecurityLabel(C.PUBLIC, I.LOW), SecurityLabel(C.PUBLIC, I.LOW)
    )

def test_can_flow_blocked_higher_confidentiality():
    # SECRET cannot flow to PUBLIC (BLP violation)
    assert not SecurityLattice.can_flow(
        SecurityLabel(C.SECRET, I.HIGH), SecurityLabel(C.PUBLIC, I.LOW)
    )

def test_can_flow_blocked_lower_integrity():
    # LOW integrity cannot flow to HIGH integrity destination (Biba violation)
    assert not SecurityLattice.can_flow(
        SecurityLabel(C.PUBLIC, I.LOW), SecurityLabel(C.PUBLIC, I.HIGH)
    )

def test_join_takes_max_conf_min_integ():
    a = SecurityLabel(C.CONFIDENTIAL, I.HIGH)
    b = SecurityLabel(C.PUBLIC, I.LOW)
    result = SecurityLattice.join(a, b)
    assert result.confidentiality == C.CONFIDENTIAL
    assert result.integrity == I.LOW

def test_bottom_can_flow_everywhere():
    for label in SecurityLattice.all_labels():
        # BOTTOM (PUBLIC, LOW) should be able to flow anywhere
        # where conf >= PUBLIC and integ <= LOW — only (PUBLIC, LOW) itself
        pass  # implement exhaustive check

def test_top_cannot_flow_to_lower_confidentiality():
    top = SecurityLattice.TOP
    for label in SecurityLattice.all_labels():
        if label.confidentiality < top.confidentiality:
            assert not SecurityLattice.can_flow(top, label)
