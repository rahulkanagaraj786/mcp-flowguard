import pytest
from unittest.mock import MagicMock
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.policy.types import Decision, FlowDecision
from flowguard.monitor.context import SessionContext
from flowguard.monitor.labeler import LabelAssigner
from flowguard.monitor.interceptor import ToolCallInterceptor

@pytest.fixture
def interceptor():
    # Mock PolicyEngine to return ALLOW if dest is >= source, else BLOCK
    engine = MagicMock()
    def mock_evaluate(request):
        if SecurityLattice.can_flow(request.source_label, request.dest_label):
            return FlowDecision(Decision.ALLOW, request, "Allowed")
        return FlowDecision(Decision.BLOCK, request, "Blocked")
    engine.evaluate.side_effect = mock_evaluate
    
    tool_labels = {
        "public_tool": SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW),
        "secret_tool": SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    }
    labeler = LabelAssigner(tool_labels, [])
    context = SessionContext("session-int")
    logger = MagicMock()
    
    return ToolCallInterceptor(engine, labeler, context, logger)

def test_pre_call_check_clean_context(interceptor):
    # Context is BOTTOM, so it can flow anywhere (e.g. public_tool)
    decision = interceptor.pre_call_check("public_tool")
    assert decision.decision == Decision.ALLOW

def test_post_call_process_taints_context(interceptor):
    # Read from secret_tool, context should become SECRET
    label = interceptor.post_call_process("secret_tool", "secret data")
    assert label == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    assert interceptor.propagator.get_flow_source_label() == SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.LOW)

def test_pre_call_check_blocked(interceptor):
    # Read secret data first
    interceptor.post_call_process("secret_tool", "secret data")
    
    # Try to write to public tool
    decision = interceptor.pre_call_check("public_tool")
    assert decision.decision == Decision.BLOCK
