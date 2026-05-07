import pytest
from flowguard.logging.structured import StructuredLogger
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel
from flowguard.policy.types import Decision, FlowRequest, FlowDecision

def test_structured_logger(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = StructuredLogger(str(log_file))
    
    # Log a taint
    label = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    logger.log_taint("test_tool", label, "preview data")
    
    # Log a decision
    req = FlowRequest("src", "dest", label, label, "sess-1")
    dec = FlowDecision(Decision.ALLOW, req, "test")
    logger.log_decision(dec)
    
    events = logger.get_events()
    assert len(events) == 2
    
    assert events[0]["type"] == "taint_assignment"
    assert events[0]["tool_name"] == "test_tool"
    assert events[0]["label"] == str(label)
    
    assert events[1]["type"] == "flow_decision"
    assert events[1]["decision"] == "ALLOW"
    assert events[1]["source_tool"] == "src"
    assert events[1]["dest_tool"] == "dest"
