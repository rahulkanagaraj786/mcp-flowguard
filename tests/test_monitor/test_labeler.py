import pytest
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.monitor.labeler import LabelAssigner

@pytest.fixture
def labeler():
    tool_labels = {
        "safe_tool": SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH),
        "secret_tool": SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    }
    content_rules = [
        {
            "pattern": r"SSN|social\.security",
            "confidentiality": "CONFIDENTIAL",
            "integrity": "HIGH"
        },
        {
            "pattern": r"API_KEY",
            "confidentiality": "SECRET",
            "integrity": "HIGH"
        }
    ]
    return LabelAssigner(tool_labels, content_rules)

def test_get_tool_clearance(labeler):
    assert labeler.get_tool_clearance("safe_tool") == SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    assert labeler.get_tool_clearance("secret_tool") == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    assert labeler.get_tool_clearance("unknown_tool") == SecurityLattice.BOTTOM

def test_assign_label_no_upgrade(labeler):
    # Output matches no rules
    label = labeler.assign_label("safe_tool", "Just some normal text.")
    assert label == SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)

def test_assign_label_with_upgrade(labeler):
    # Matches SSN rule which is CONFIDENTIAL
    label = labeler.assign_label("safe_tool", "My SSN is 123-45-678")
    assert label == SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)

def test_assign_label_cannot_downgrade(labeler):
    # Base label is SECRET. Matches SSN rule (CONFIDENTIAL). 
    # Result should stay SECRET because join(SECRET, CONFIDENTIAL) = SECRET.
    label = labeler.assign_label("secret_tool", "My SSN is 123")
    assert label == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
