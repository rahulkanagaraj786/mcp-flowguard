"""PolicyEngine evaluation."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.policy.engine import PolicyEngine
from flowguard.policy.exceptions import PolicyLoadError
from flowguard.policy.types import Decision, FlowRequest


def _ts() -> datetime:
    return datetime.now(timezone.utc)


def test_exfiltration_blocked_by_lattice_default_policy(default_policy_path: Path) -> None:
    eng = PolicyEngine(default_policy_path)
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="web_fetch",
        source_label=SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH),
        dest_label=eng.get_tool_label("web_fetch"),
        session_id="s1",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert fd.matched_rule is None
    assert "Lattice violation" in fd.reason


def test_integrity_poison_blocked_by_lattice(default_policy_path: Path) -> None:
    eng = PolicyEngine(default_policy_path)
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="filesystem",
        source_label=SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW),
        dest_label=eng.get_tool_label("filesystem"),
        session_id="s1",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert "integrity" in fd.reason.lower() or "Biba" in fd.reason


def test_safe_flow_allow(default_policy_path: Path) -> None:
    eng = PolicyEngine(default_policy_path)
    wf = eng.get_tool_label("web_fetch")
    bottom = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="web_fetch",
        source_label=bottom,
        dest_label=wf,
        session_id="s1",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.ALLOW
    assert fd.matched_rule is not None


def test_lattice_blocks_even_when_permissive_yaml_weak(permissive_policy_path: Path) -> None:
    eng = PolicyEngine(permissive_policy_path)
    wf = eng.get_tool_label("web_fetch")
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="web_fetch",
        source_label=SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH),
        dest_label=wf,
        session_id="s1",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert "Lattice violation" in fd.reason


def test_default_deny_reason_distinct(tmp_path: Path) -> None:
    """Lattice permits PUBLIC→PUBLIC but no rule matches → default deny wording."""
    p = tmp_path / "minimal.yaml"
    p.write_text(
        """
tool_labels:
  web_fetch: { confidentiality: PUBLIC, integrity: LOW }
rules:
  - name: unused-block-secret
    source_tools: ["*"]
    dest_tools: ["web_fetch"]
    min_confidentiality: SECRET
    action: BLOCK
"""
    )
    eng = PolicyEngine(p)
    lbl = eng.get_tool_label("web_fetch")
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="web_fetch",
        source_label=lbl,
        dest_label=lbl,
        session_id="s",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert "Default Deny" in fd.reason
    assert "Lattice violation" not in fd.reason
    assert fd.matched_rule is None


def test_empty_rules_list_default_denies_even_lattice_safe_flow(tmp_path: Path) -> None:
    """Fail-safe: no explicit ALLOW ⇒ BLOCK even for BOTTOM→BOTTOM lattice-safe flow."""
    p = tmp_path / "empty_rules.yaml"
    p.write_text(
        """
tool_labels:
  web_fetch: { confidentiality: PUBLIC, integrity: LOW }
rules: []
"""
    )
    eng = PolicyEngine(p)
    wf = eng.get_tool_label("web_fetch")
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="web_fetch",
        source_label=wf,
        dest_label=wf,
        session_id="s",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert fd.matched_rule is None
    assert fd.reason == PolicyEngine._DEFAULT_DENY_REASON


def test_unknown_tool_raises(default_policy_path: Path) -> None:
    eng = PolicyEngine(default_policy_path)
    with pytest.raises(PolicyLoadError):
        eng.get_tool_label("nonexistent_tool")


def test_confidential_to_email_blocked_by_lattice_first(default_policy_path: Path) -> None:
    """Email is labeled INTERNAL; CONFIDENTIAL source cannot satisfy source.conf <= dest.conf."""
    eng = PolicyEngine(default_policy_path)
    req = FlowRequest(
        source_tool="llm_context",
        dest_tool="email",
        source_label=SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH),
        dest_label=eng.get_tool_label("email"),
        session_id="s1",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.BLOCK
    assert "Lattice violation" in fd.reason


def test_policy_rule_warn_takes_effect_when_lattice_allows(tmp_path: Path) -> None:
    """Dedicated policy: dest clearance fits CONFIDENTIAL so WARN rule applies."""
    p = tmp_path / "warn.yaml"
    p.write_text(
        """
tool_labels:
  sink: { confidentiality: CONFIDENTIAL, integrity: MEDIUM }
rules:
  - name: warn-conf-to-sink
    source_tools: ["*"]
    dest_tools: ["sink"]
    min_confidentiality: CONFIDENTIAL
    max_confidentiality: CONFIDENTIAL
    action: WARN
  - name: allow
    source_tools: ["*"]
    dest_tools: ["sink"]
    action: ALLOW
"""
    )
    eng = PolicyEngine(p)
    req = FlowRequest(
        source_tool="ctx",
        dest_tool="sink",
        source_label=SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH),
        dest_label=eng.get_tool_label("sink"),
        session_id="s",
        timestamp=_ts(),
    )
    fd = eng.evaluate(req)
    assert fd.decision == Decision.WARN
    assert fd.matched_rule and fd.matched_rule.name == "warn-conf-to-sink"
