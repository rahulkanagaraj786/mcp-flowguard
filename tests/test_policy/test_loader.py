"""Policy YAML loading."""

from pathlib import Path

import pytest

from flowguard.policy.exceptions import PolicyLoadError
from flowguard.policy.loader import PolicyLoader


def test_load_default_policy(default_policy_path: Path) -> None:
    rules, tools = PolicyLoader.load(default_policy_path)
    assert set(tools.keys()) == {"filesystem", "database", "web_fetch", "email"}
    assert tools["web_fetch"]["confidentiality"] == "PUBLIC"
    names = {r.name for r in rules}
    assert "block-confidential-plus-to-web" in names
    assert "allow-public-low-to-web-fetch" in names


def test_load_strict_policy(strict_policy_path: Path) -> None:
    rules, tools = PolicyLoader.load(strict_policy_path)
    assert tools["filesystem"]["confidentiality"] == "SECRET"
    assert any(r.name == "block-from-web-fetch-tool" for r in rules)


def test_load_permissive_policy(permissive_policy_path: Path) -> None:
    rules, tools = PolicyLoader.load(permissive_policy_path)
    assert tools["filesystem"]["integrity"] == "MEDIUM"
    assert len(rules) >= 1


def test_invalid_level_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(
        """
tool_labels:
  x: { confidentiality: NOT_A_LEVEL, integrity: LOW }
rules:
  - name: r
    source_tools: ["*"]
    dest_tools: ["*"]
    action: ALLOW
"""
    )
    with pytest.raises(PolicyLoadError):
        PolicyLoader.load(p)


def test_unknown_tool_in_rule_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad2.yaml"
    p.write_text(
        """
tool_labels:
  a: { confidentiality: PUBLIC, integrity: LOW }
rules:
  - name: r
    source_tools: ["unknown_tool"]
    dest_tools: ["*"]
    action: BLOCK
"""
    )
    with pytest.raises(PolicyLoadError, match="unknown"):
        PolicyLoader.load(p)
