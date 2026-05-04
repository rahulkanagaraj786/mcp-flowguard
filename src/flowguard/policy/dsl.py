"""Match policy rules with specificity ordering."""

from __future__ import annotations

from flowguard.lattice.labels import SecurityLabel
from flowguard.policy.parsing import parse_confidentiality, parse_integrity
from flowguard.policy.types import PolicyRule


class PolicyRuleSet:
    """Evaluate which rules apply to a flow, most-specific first."""

    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = list(rules)

    def find_matching_rules(
        self,
        source_tool: str,
        dest_tool: str,
        source_label: SecurityLabel,
    ) -> list[PolicyRule]:
        matched: list[PolicyRule] = []
        for rule in self._rules:
            if not self._matches_tool(source_tool, rule.source_tools):
                continue
            if not self._matches_tool(dest_tool, rule.dest_tools):
                continue
            if not self._label_constraints_ok(rule, source_label):
                continue
            matched.append(rule)

        matched.sort(key=self._specificity_score, reverse=True)
        return matched

    @staticmethod
    def _matches_tool(tool_name: str, patterns: list[str]) -> bool:
        if "*" in patterns:
            return True
        return tool_name in patterns

    @staticmethod
    def _specificity_score(rule: PolicyRule) -> int:
        src_wild = "*" in rule.source_tools
        dst_wild = "*" in rule.dest_tools
        return (0 if src_wild else 1) + (0 if dst_wild else 1)

    @staticmethod
    def _label_constraints_ok(rule: PolicyRule, source: SecurityLabel) -> bool:
        if rule.min_confidentiality is not None:
            thr = parse_confidentiality(rule.min_confidentiality)
            if source.confidentiality < thr:
                return False
        if rule.max_confidentiality is not None:
            thr = parse_confidentiality(rule.max_confidentiality)
            if source.confidentiality > thr:
                return False
        if rule.min_integrity is not None:
            thr = parse_integrity(rule.min_integrity)
            if source.integrity < thr:
                return False
        if rule.max_integrity is not None:
            thr = parse_integrity(rule.max_integrity)
            if source.integrity > thr:
                return False
        return True
