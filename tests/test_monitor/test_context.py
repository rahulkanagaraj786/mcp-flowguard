import pytest
import datetime
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.monitor.context import SessionContext, TaintedData
from flowguard.policy.types import Decision

def test_add_single_taint():
    ctx = SessionContext("session-1")
    label = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    data = TaintedData(
        content_hash="hash1", 
        label=label, 
        source_tool="tool1", 
        timestamp=datetime.datetime.utcnow(), 
        content_preview="preview"
    )
    ctx.add_taint(data)
    assert ctx.get_context_label() == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)

def test_add_multiple_taint():
    ctx = SessionContext("session-2")
    label1 = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    label2 = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)
    data1 = TaintedData("hash1", label1, "tool1", datetime.datetime.utcnow(), "prev1")
    data2 = TaintedData("hash2", label2, "tool2", datetime.datetime.utcnow(), "prev2")
    
    ctx.add_taint(data1)
    ctx.add_taint(data2)
    
    # The join of (PUBLIC, HIGH) and (SECRET, LOW) should be (SECRET, HIGH)
    expected_label = SecurityLattice.join(label1, label2)
    assert ctx.get_context_label() == expected_label

def test_clear_context():
    ctx = SessionContext("session-3")
    label = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    data = TaintedData("hash1", label, "tool1", datetime.datetime.utcnow(), "prev1")
    ctx.add_taint(data)
    
    assert ctx.get_context_label() == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)
    ctx.clear()
    assert ctx.get_context_label() == SecurityLattice.BOTTOM
    assert len(ctx.tainted_data) == 0

def test_record_flow():
    ctx = SessionContext("session-4")
    label = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    ctx.record_flow("source", "dest", label, Decision.ALLOW, "Testing")
    
    assert len(ctx.flow_log) == 1
    record = ctx.flow_log[0]
    assert record["source_tool"] == "source"
    assert record["dest_tool"] == "dest"
    assert record["decision"] == Decision.ALLOW.value
    assert record["reason"] == "Testing"
    assert "timestamp" in record
