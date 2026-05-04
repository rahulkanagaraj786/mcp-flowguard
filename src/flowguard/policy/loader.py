"""Load policy YAML into rules and raw tool label mappings."""

from __future__ import annotations

from pathlib import Path
from typing import Any, MutableMapping, cast

import yaml

from flowguard.policy.exceptions import PolicyLoadError
from flowguard.policy.parsing import parse_confidentiality, parse_integrity
from flowguard.policy.types import Decision, PolicyRule


class PolicyLoader:
    """Fail-safe policy loading — invalid configuration raises PolicyLoadError."""

    @staticmethod
    def load(path: Path) -> tuple[list[PolicyRule], dict[str, MutableMapping[str, str]]]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyLoadError(f"Cannot read policy file: {path}") from exc

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"Invalid YAML in {path}") from exc

        if not isinstance(data, dict):
            raise PolicyLoadError("Policy root must be a mapping")

        raw_tools = data.get("tool_labels")
        raw_rules = data.get("rules")
        if raw_tools is None:
            raise PolicyLoadError("Policy must define 'tool_labels'")
        if raw_rules is None:
            raise PolicyLoadError("Policy must define 'rules'")

        if not isinstance(raw_tools, dict):
            raise PolicyLoadError("'tool_labels' must be a mapping")
        if not raw_tools:
            raise PolicyLoadError("'tool_labels' must not be empty")
        if not isinstance(raw_rules, list):
            raise PolicyLoadError("'rules' must be a list")

        tool_labels: dict[str, MutableMapping[str, str]] = {}
        for tool_name, spec in raw_tools.items():
            if not isinstance(tool_name, str) or not isinstance(spec, dict):
                raise PolicyLoadError(f"Invalid tool_labels entry: {tool_name!r}")
            conf_s = spec.get("confidentiality")
            integ_s = spec.get("integrity")
            if not isinstance(conf_s, str) or not isinstance(integ_s, str):
                raise PolicyLoadError(f"Tool {tool_name!r} needs string confidentiality/integrity")
            parse_confidentiality(conf_s)
            parse_integrity(integ_s)
            tool_labels[tool_name] = {
                "confidentiality": conf_s.strip(),
                "integrity": integ_s.strip(),
            }

        rules: list[PolicyRule] = []
        for i, entry in enumerate(raw_rules):
            if not isinstance(entry, dict):
                raise PolicyLoadError(f"rules[{i}] must be a mapping")
            rule = PolicyLoader._parse_rule(entry, index=i)
            rules.append(rule)

        PolicyLoader._validate_rule_tools(rules, set(tool_labels.keys()))

        return rules, tool_labels

    @staticmethod
    def _parse_rule(entry: dict[str, Any], *, index: int) -> PolicyRule:
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PolicyLoadError(f"rules[{index}] missing non-empty 'name'")

        src = entry.get("source_tools")
        dst = entry.get("dest_tools")
        act = entry.get("action")
        if not isinstance(src, list) or not src or not all(isinstance(x, str) for x in src):
            raise PolicyLoadError(f"Rule {name!r}: source_tools must be a non-empty list of strings")
        if not isinstance(dst, list) or not dst or not all(isinstance(x, str) for x in dst):
            raise PolicyLoadError(f"Rule {name!r}: dest_tools must be a non-empty list of strings")
        if not isinstance(act, str):
            raise PolicyLoadError(f"Rule {name!r}: action must be a string")

        try:
            decision = Decision(act.strip().upper())
        except ValueError as exc:
            raise PolicyLoadError(f"Rule {name!r}: invalid action {act!r}") from exc

        desc = entry.get("description")
        if desc is not None and not isinstance(desc, str):
            raise PolicyLoadError(f"Rule {name!r}: description must be a string")

        optional_str_fields = (
            "min_confidentiality",
            "max_confidentiality",
            "min_integrity",
            "max_integrity",
        )
        kwargs: dict[str, Any] = {}
        for field in optional_str_fields:
            val = entry.get(field)
            if val is None:
                kwargs[field] = None
            elif isinstance(val, str):
                kwargs[field] = val.strip()
                if field.endswith("confidentiality"):
                    parse_confidentiality(cast(str, kwargs[field]))
                elif field.endswith("integrity"):
                    parse_integrity(cast(str, kwargs[field]))
            else:
                raise PolicyLoadError(f"Rule {name!r}: {field} must be a string or omitted")

        return PolicyRule(
            name=name.strip(),
            source_tools=list(src),
            dest_tools=list(dst),
            action=decision,
            description=desc.strip() if isinstance(desc, str) else None,
            min_confidentiality=kwargs["min_confidentiality"],
            max_confidentiality=kwargs["max_confidentiality"],
            min_integrity=kwargs["min_integrity"],
            max_integrity=kwargs["max_integrity"],
        )

    @staticmethod
    def _validate_rule_tools(rules: list[PolicyRule], known_tools: set[str]) -> None:
        for rule in rules:
            for label, tools in (
                ("source", rule.source_tools),
                ("dest", rule.dest_tools),
            ):
                for t in tools:
                    if t == "*":
                        continue
                    if t not in known_tools:
                        raise PolicyLoadError(
                            f"Rule {rule.name!r} references unknown {label} tool {t!r}"
                        )
