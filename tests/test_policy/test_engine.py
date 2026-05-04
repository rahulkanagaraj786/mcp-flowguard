from pathlib import Path
from flowguard.policy.engine import PolicyEngine
from flowguard.policy.types import FlowRequest, Decision
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel as C, IntegrityLevel as I
from datetime import datetime

def make_request(src_tool, dst_tool, src_conf, src_integ, dst_conf, dst_integ):
    return FlowRequest(
        source_tool=src_tool,
        dest_tool=dst_tool,
        source_label=SecurityLabel(src_conf, src_integ),
        dest_label=SecurityLabel(dst_conf, dst_integ),
        session_id="test",
        timestamp=datetime.utcnow(),
    )

def test_exfiltration_is_blocked(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    req = make_request("filesystem", "web_fetch", C.CONFIDENTIAL, I.HIGH, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK

def test_integrity_poison_is_blocked(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    req = make_request("web_fetch", "filesystem", C.PUBLIC, I.LOW, C.CONFIDENTIAL, I.HIGH)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK

def test_safe_flow_is_allowed(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    # PUBLIC LOW -> PUBLIC LOW is always safe
    req = make_request("web_fetch", "web_fetch", C.PUBLIC, I.LOW, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.ALLOW

def test_lattice_block_cannot_be_overridden(permissive_policy_path):
    # Even with a permissive policy, lattice violation is always BLOCK
    engine = PolicyEngine(permissive_policy_path)
    req = make_request("filesystem", "web_fetch", C.SECRET, I.HIGH, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK
