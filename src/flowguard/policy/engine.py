from pathlib import Path
from flowguard.policy.types import FlowRequest, FlowDecision, Decision
from flowguard.policy.dsl import PolicyRuleSet
from flowguard.policy.loader import PolicyLoader
from flowguard.policy.types import PolicyRule
from flowguard.lattice.lattice import SecurityLattice
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


class PolicyEngine:
    """
    The decision engine. Given a FlowRequest, returns a FlowDecision.
    
    Evaluation order:
    1. Lattice check (BLP + Biba) — always applied, cannot be overridden
    2. Explicit rules — most restrictive wins (BLOCK > WARN > ALLOW)
    3. Default: ALLOW if lattice permits and no rule matches
    """

    _PRECEDENCE = {Decision.BLOCK: 2, Decision.WARN: 1, Decision.ALLOW: 0}

    def __init__(self, policy_path: Path) -> None:
        rules, tool_labels_raw = PolicyLoader.load(policy_path)
        self._ruleset = PolicyRuleSet(rules)
        self._tool_labels = self._parse_tool_labels(tool_labels_raw)

    def evaluate(self, request: FlowRequest) -> FlowDecision:
        # Step 1: Lattice check — hard block, no rule can override
        if not SecurityLattice.can_flow(request.source_label, request.dest_label):
            return FlowDecision(
                decision=Decision.BLOCK,
                request=request,
                reason=(
                    f"Lattice violation: {request.source_label} cannot flow to "
                    f"{request.dest_label} (BLP/Biba)"
                ),
            )

        # Step 2: Explicit rules
        matching = self._ruleset.find_matching_rules(
            request.source_tool, request.dest_tool, request.source_label
        )
        if matching:
            worst = max(matching, key=lambda r: self._PRECEDENCE[r.action])
            return FlowDecision(
                decision=worst.action,
                request=request,
                reason=worst.description or f"Matched rule: {worst.name}",
                matched_rule=worst.name,
            )

        # Step 3: Default allow
        return FlowDecision(
            decision=Decision.ALLOW,
            request=request,
            reason="No matching rule; lattice permits flow",
        )

    def get_tool_label(self, tool_name: str) -> SecurityLabel:
        """Get the default security label for a tool's output."""
        return self._tool_labels.get(tool_name, SecurityLattice.BOTTOM)

    @staticmethod
    def _parse_tool_labels(raw: dict) -> dict[str, SecurityLabel]:
        result = {}
        for tool, levels in raw.items():
            result[tool] = SecurityLabel(
                confidentiality=ConfidentialityLevel[levels["confidentiality"]],
                integrity=IntegrityLevel[levels["integrity"]],
            )
        return result
