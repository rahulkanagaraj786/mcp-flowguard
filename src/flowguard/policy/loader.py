from pathlib import Path
from typing import Any
import yaml
from flowguard.policy.types import PolicyRule, Decision


class PolicyLoader:

    @staticmethod
    def load(path: Path) -> tuple[list[PolicyRule], dict[str, dict]]:
        """Load policy from YAML. Returns (rules, tool_labels_raw).
        tool_labels_raw is a dict like:
          {"filesystem": {"confidentiality": "CONFIDENTIAL", "integrity": "HIGH"}, ...}
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        rules = [PolicyLoader._parse_rule(r) for r in data.get("rules", [])]
        tool_labels = data.get("tool_labels", {})
        return rules, tool_labels

    @staticmethod
    def _parse_rule(raw: dict[str, Any]) -> PolicyRule:
        return PolicyRule(
            name=raw["name"],
            source_tools=raw.get("source_tools", ["*"]),
            dest_tools=raw.get("dest_tools", ["*"]),
            action=Decision(raw["action"]),
            description=raw.get("description", ""),
            min_confidentiality=raw.get("min_confidentiality"),
            max_confidentiality=raw.get("max_confidentiality"),
            min_integrity=raw.get("min_integrity"),
            max_integrity=raw.get("max_integrity"),
        )