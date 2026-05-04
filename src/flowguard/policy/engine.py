"""Policy decision engine: lattice first, then rules, then default deny."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.lattice import SecurityLattice
from flowguard.policy.dsl import PolicyRuleSet
from flowguard.policy.exceptions import PolicyLoadError
from flowguard.policy.loader import PolicyLoader
from flowguard.policy.parsing import parse_confidentiality, parse_integrity
from flowguard.policy.types import Decision, FlowDecision, FlowRequest, PolicyRule


class PolicyEngine:
    """Loads YAML policy and evaluates flows (MAC lattice + DAC rules)."""

    _DEFAULT_DENY_REASON = (
        "Lattice permitted flow, but no explicit policy rule allowed it (Default Deny)."
    )

    def __init__(self, policy_path: Path) -> None:
        rules, raw_tools = PolicyLoader.load(policy_path)
        self._rule_set = PolicyRuleSet(rules)
        self._raw_tool_labels = raw_tools
        self._tool_labels: dict[str, SecurityLabel] = {
            name: SecurityLabel(
                confidentiality=parse_confidentiality(spec["confidentiality"]),
                integrity=parse_integrity(spec["integrity"]),
            )
            for name, spec in raw_tools.items()
        }

    def get_tool_label(self, tool_name: str) -> SecurityLabel:
        if tool_name not in self._tool_labels:
            raise PolicyLoadError(f"Unknown tool {tool_name!r} — not defined in policy tool_labels")
        return self._tool_labels[tool_name]

    def evaluate(self, request: FlowRequest) -> FlowDecision:
        now = datetime.now(timezone.utc)

        if not SecurityLattice.can_flow(request.source_label, request.dest_label):
            reason = self._lattice_block_reason(request.source_label, request.dest_label)
            return FlowDecision(
                decision=Decision.BLOCK,
                request=request,
                reason=reason,
                matched_rule=None,
                timestamp=now,
            )

        matched = self._rule_set.find_matching_rules(
            request.source_tool,
            request.dest_tool,
            request.source_label,
        )

        if not matched:
            return FlowDecision(
                decision=Decision.BLOCK,
                request=request,
                reason=self._DEFAULT_DENY_REASON,
                matched_rule=None,
                timestamp=now,
            )

        decision, winner = self._pick_winning_rule(matched)
        reason = self._policy_reason(decision, winner)

        return FlowDecision(
            decision=decision,
            request=request,
            reason=reason,
            matched_rule=winner,
            timestamp=now,
        )

    @staticmethod
    def _pick_winning_rule(matched: list[PolicyRule]) -> tuple[Decision, PolicyRule]:
        """Prefer BLOCK > WARN > ALLOW; tie-break by specificity order (list already sorted)."""
        for rule in matched:
            if rule.action == Decision.BLOCK:
                return Decision.BLOCK, rule
        for rule in matched:
            if rule.action == Decision.WARN:
                return Decision.WARN, rule
        return Decision.ALLOW, matched[0]

    @staticmethod
    def _lattice_block_reason(src: SecurityLabel, dst: SecurityLabel) -> str:
        parts = []
        if src.confidentiality > dst.confidentiality:
            parts.append(
                "Lattice violation: source confidentiality exceeds destination clearance (BLP *-property / no write-down)."
            )
        if src.integrity < dst.integrity:
            parts.append(
                "Lattice violation: source integrity is below destination requirement (Biba *-property / no write-up)."
            )
        if not parts:
            parts.append("Lattice violation: flow not permitted by security lattice.")
        return " ".join(parts)

    @staticmethod
    def _policy_reason(decision: Decision, rule: PolicyRule) -> str:
        return f"Policy rule '{rule.name}' matched (action: {decision})."
