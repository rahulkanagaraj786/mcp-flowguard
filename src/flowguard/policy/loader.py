from pathlib import Path
from typing import Any
import yaml
from flowguard.policy.types import PolicyRule, Decision
from flowguard.policy.exceptions import PolicyLoadError
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel

_VALID_CONF = {l.name for l in ConfidentialityLevel}
_VALID_INTEG = {l.name for l in IntegrityLevel}


class PolicyLoader:

    @staticmethod
    def load(path: Path) -> tuple[list[PolicyRule], dict[str, dict]]:
        """Load policy from YAML. Returns (rules, tool_labels_raw).
        tool_labels_raw is a dict like:
          {"filesystem": {"confidentiality": "CONFIDENTIAL", "integrity": "HIGH"}, ...}
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        tool_labels = data.get("tool_labels", {})
        PolicyLoader._validate_tool_labels(tool_labels)

        known_tools = set(tool_labels.keys()) | {"*"}
        rules = [PolicyLoader._parse_rule(r, known_tools) for r in data.get("rules", [])]
        return rules, tool_labels

    @staticmethod
    def _validate_tool_labels(tool_labels: dict[str, Any]) -> None:
        for tool, levels in tool_labels.items():
            conf = levels.get("confidentiality", "")
            integ = levels.get("integrity", "")
            if conf not in _VALID_CONF:
                raise PolicyLoadError(
                    f"Tool '{tool}': invalid confidentiality level '{conf}'. "
                    f"Valid values: {sorted(_VALID_CONF)}"
                )
            if integ not in _VALID_INTEG:
                raise PolicyLoadError(
                    f"Tool '{tool}': invalid integrity level '{integ}'. "
                    f"Valid values: {sorted(_VALID_INTEG)}"
                )

    @staticmethod
    def _parse_rule(raw: dict[str, Any], known_tools: set[str]) -> PolicyRule:
        for tool in raw.get("source_tools", []):
            if tool not in known_tools:
                raise PolicyLoadError(
                    f"Rule '{raw.get('name')}': unknown source tool '{tool}'"
                )
        for tool in raw.get("dest_tools", []):
            if tool not in known_tools:
                raise PolicyLoadError(
                    f"Rule '{raw.get('name')}': unknown dest tool '{tool}'"
                )
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
