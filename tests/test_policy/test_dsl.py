"""PolicyRuleSet matching and specificity."""

from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.policy.dsl import PolicyRuleSet
from flowguard.policy.types import Decision, PolicyRule


def _rules() -> list[PolicyRule]:
    return [
        PolicyRule(
            name="specific",
            source_tools=["filesystem"],
            dest_tools=["web_fetch"],
            action=Decision.BLOCK,
        ),
        PolicyRule(
            name="wildcard-dest",
            source_tools=["filesystem"],
            dest_tools=["*"],
            action=Decision.WARN,
        ),
        PolicyRule(
            name="catch-all",
            source_tools=["*"],
            dest_tools=["*"],
            action=Decision.ALLOW,
        ),
    ]


def test_specificity_orders_non_wildcard_first() -> None:
    rs = PolicyRuleSet(_rules())
    out = rs.find_matching_rules(
        "filesystem",
        "web_fetch",
        SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH),
    )
    assert [r.name for r in out] == ["specific", "wildcard-dest", "catch-all"]


def test_wildcard_matches_any_tool() -> None:
    rs = PolicyRuleSet(_rules())
    out = rs.find_matching_rules(
        "database",
        "email",
        SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW),
    )
    assert len(out) == 1 and out[0].name == "catch-all"


def test_label_threshold_min_confidentiality() -> None:
    rules = [
        PolicyRule(
            name="high-only",
            source_tools=["*"],
            dest_tools=["*"],
            action=Decision.BLOCK,
            min_confidentiality="CONFIDENTIAL",
        ),
    ]
    rs = PolicyRuleSet(rules)
    pub = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    sec = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    assert rs.find_matching_rules("a", "b", pub) == []
    assert len(rs.find_matching_rules("a", "b", sec)) == 1


def test_secret_secret_allow_public_min_still_matches_section_7_7() -> None:
    """§7.7: true source label must be used — SECRET satisfies min PUBLIC."""
    rules = [
        PolicyRule(
            name="allow-low-clearance",
            source_tools=["*"],
            dest_tools=["email"],
            action=Decision.ALLOW,
            min_confidentiality="PUBLIC",
        ),
    ]
    rs = PolicyRuleSet(rules)
    src = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)
    dst_tool = "email"
    matched = rs.find_matching_rules("llm_context", dst_tool, src)
    assert len(matched) == 1 and matched[0].name == "allow-low-clearance"


def test_max_integrity_low_triggers_on_low_source() -> None:
    rules = [
        PolicyRule(
            name="low-trust-only",
            source_tools=["*"],
            dest_tools=["*"],
            action=Decision.BLOCK,
            max_integrity="LOW",
        ),
    ]
    rs = PolicyRuleSet(rules)
    low = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    high = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.HIGH)
    assert len(rs.find_matching_rules("x", "y", low)) == 1
    assert rs.find_matching_rules("x", "y", high) == []
