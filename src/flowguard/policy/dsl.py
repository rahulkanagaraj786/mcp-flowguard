from flowguard.policy.types import PolicyRule, Decision
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel


class PolicyRuleSet:

    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = rules

    def find_matching_rules(
        self,
        source_tool: str,
        dest_tool: str,
        source_label: SecurityLabel,
    ) -> list[PolicyRule]:
        """Return all rules that match this flow, ordered most-specific first."""
        matched = []
        for rule in self._rules:
            if (self._matches_tool(source_tool, rule.source_tools)
                    and self._matches_tool(dest_tool, rule.dest_tools)
                    and self._matches_label(rule, source_label)):
                matched.append(rule)
        # Most specific first: non-wildcard rules before wildcard rules
        matched.sort(key=lambda r: ("*" in r.source_tools) + ("*" in r.dest_tools))
        return matched

    @staticmethod
    def _matches_tool(tool: str, patterns: list[str]) -> bool:
        return "*" in patterns or tool in patterns

    @staticmethod
    def _matches_label(rule: PolicyRule, label: SecurityLabel) -> bool:
        if rule.min_confidentiality:
            if label.confidentiality < ConfidentialityLevel[rule.min_confidentiality]:
                return False
        if rule.max_confidentiality:
            if label.confidentiality > ConfidentialityLevel[rule.max_confidentiality]:
                return False
        if rule.min_integrity:
            if label.integrity < IntegrityLevel[rule.min_integrity]:
                return False
        if rule.max_integrity:
            if label.integrity > IntegrityLevel[rule.max_integrity]:
                return False
        return True