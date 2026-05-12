import pytest
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.monitor.context import SessionContext
from flowguard.monitor.propagation import TaintPropagator

def test_on_tool_output():
    ctx = SessionContext("test-1")
    prop = TaintPropagator(ctx)
    
    label1 = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    prop.on_tool_output("tool1", "content1", label1)
    
    # join of initial (PUBLIC, HIGH) and (PUBLIC, HIGH) = (PUBLIC, HIGH)
    assert prop.get_flow_source_label() == SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    
    label2 = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)
    prop.on_tool_output("tool2", "content2", label2)
    
    # Should join both labels
    expected = SecurityLattice.join(label1, label2)
    assert prop.get_flow_source_label() == expected

def test_reset():
    ctx = SessionContext("test-2")
    prop = TaintPropagator(ctx)
    label1 = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    prop.on_tool_output("tool1", "content1", label1)
    
    prop.reset()
    assert prop.get_flow_source_label() == SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    assert len(ctx.tainted_data) == 0
