# Phase 1: Policy Engine — Spec Sheet

**Owner:** Teammate 1  
**Depends on:** Nothing (pure Python, no MCP SDK needed)  
**Other components depend on:** `SecurityLabel`, `PolicyEngine.evaluate()`

---

## Goal

Build the theoretical core of FlowGuard: a 2D security lattice combining Bell-LaPadula (confidentiality) and Biba (integrity), a YAML-based policy DSL, and a decision engine that takes a flow request and returns ALLOW / WARN / BLOCK.

---

## Project Setup (do this first)

### Directory structure to create

```
mcp-flowguard/
├── pyproject.toml
├── src/
│   └── flowguard/
│       ├── __init__.py
│       ├── lattice/
│       │   ├── __init__.py
│       │   ├── levels.py
│       │   ├── labels.py
│       │   └── lattice.py
│       └── policy/
│           ├── __init__.py
│           ├── types.py
│           ├── loader.py
│           ├── dsl.py
│           └── engine.py
├── policies/
│   ├── default_policy.yaml
│   ├── strict_policy.yaml
│   └── permissive_policy.yaml
└── tests/
    ├── conftest.py
    ├── test_lattice/
    │   ├── __init__.py
    │   ├── test_levels.py
    │   ├── test_labels.py
    │   └── test_lattice.py
    └── test_policy/
        ├── __init__.py
        ├── test_loader.py
        ├── test_dsl.py
        └── test_engine.py
```

### `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "mcp-flowguard"
version = "0.1.0"
description = "Runtime information flow enforcement for MCP-based LLM pipelines"
requires-python = ">=3.11"
dependencies = [
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.0.0",
]

[tool.hatch.build.targets.wheel]
packages = ["src/flowguard"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

Install with: `pip install -e ".[dev]"`

---

## File 1: `src/flowguard/lattice/levels.py`

```python
import enum

class ConfidentialityLevel(enum.IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3

class IntegrityLevel(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
```

**Why `IntEnum`:** comparison operators (`<=`, `>=`) work natively, mapping directly to the lattice partial order.

---

## File 2: `src/flowguard/lattice/labels.py`

```python
from dataclasses import dataclass
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel

@dataclass(frozen=True, order=False)
class SecurityLabel:
    confidentiality: ConfidentialityLevel
    integrity: IntegrityLevel

    def dominates(self, other: "SecurityLabel") -> bool:
        """True if self >= other in BOTH dimensions."""
        return (
            self.confidentiality >= other.confidentiality
            and self.integrity >= other.integrity
        )

    def __repr__(self) -> str:
        return f"({self.confidentiality.name}, {self.integrity.name})"
```

**Why `frozen=True`:** labels must never be mutated after assignment — this is a security invariant. Frozen dataclasses are also hashable, which is required for using labels as dict keys in taint tracking.

**Why `order=False`:** prevents dataclass auto-ordering, which would be lexicographic and wrong for a 2D lattice.

---

## File 3: `src/flowguard/lattice/lattice.py`

```python
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
from flowguard.lattice.labels import SecurityLabel

class SecurityLattice:

    BOTTOM = SecurityLabel(ConfidentialityLevel.PUBLIC, IntegrityLevel.LOW)
    TOP = SecurityLabel(ConfidentialityLevel.SECRET, IntegrityLevel.HIGH)

    @staticmethod
    def join(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Least upper bound. Used when data from two sources merges.
        Conservative: max confidentiality, min integrity."""
        return SecurityLabel(
            confidentiality=ConfidentialityLevel(max(a.confidentiality, b.confidentiality)),
            integrity=IntegrityLevel(min(a.integrity, b.integrity)),
        )

    @staticmethod
    def meet(a: SecurityLabel, b: SecurityLabel) -> SecurityLabel:
        """Greatest lower bound."""
        return SecurityLabel(
            confidentiality=ConfidentialityLevel(min(a.confidentiality, b.confidentiality)),
            integrity=IntegrityLevel(max(a.integrity, b.integrity)),
        )

    @staticmethod
    def can_flow(source: SecurityLabel, dest: SecurityLabel) -> bool:
        """Bell-LaPadula + Biba combined flow check.
        BLP: source.conf <= dest.conf  (no write up / no read down for confidentiality)
        Biba: source.integ >= dest.integ (no write down / no read up for integrity)
        """
        return (
            source.confidentiality <= dest.confidentiality
            and source.integrity >= dest.integrity
        )
```

**`join` rationale:** when the LLM absorbs outputs from two tools, the resulting taint label must be at least as restrictive as both. For confidentiality: `max` (worst case). For integrity: `min` (only as trusted as the least trusted source).

---

## File 4: `src/flowguard/policy/types.py`

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from flowguard.lattice.labels import SecurityLabel


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class FlowRequest:
    source_tool: str
    dest_tool: str
    source_label: SecurityLabel
    dest_label: SecurityLabel
    session_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FlowDecision:
    decision: Decision
    request: FlowRequest
    reason: str
    matched_rule: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyRule:
    name: str
    source_tools: list[str]         # ["*"] means any tool
    dest_tools: list[str]           # ["*"] means any tool
    action: Decision
    description: str = ""
    min_confidentiality: Optional[str] = None   # triggers when source >= this level
    max_confidentiality: Optional[str] = None   # triggers when source <= this level
    min_integrity: Optional[str] = None
    max_integrity: Optional[str] = None
```

---

## File 5: `src/flowguard/policy/loader.py`

```python
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
```

---

## File 6: `src/flowguard/policy/dsl.py`

```python
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
```

---

## File 7: `src/flowguard/policy/engine.py`

```python
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
```

---

## Policy Files

### `policies/default_policy.yaml`

```yaml
version: "1.0"
description: "Default FlowGuard policy"

tool_labels:
  filesystem:  { confidentiality: CONFIDENTIAL, integrity: HIGH }
  database:    { confidentiality: CONFIDENTIAL, integrity: HIGH }
  web_fetch:   { confidentiality: PUBLIC,       integrity: LOW  }
  email:       { confidentiality: INTERNAL,     integrity: MEDIUM }

rules:
  - name: block_exfiltration_to_web
    description: "Confidential+ data cannot flow to web_fetch"
    source_tools: ["*"]
    dest_tools: ["web_fetch"]
    min_confidentiality: CONFIDENTIAL
    action: BLOCK

  - name: block_secret_to_email
    description: "Secret data cannot flow to email"
    source_tools: ["*"]
    dest_tools: ["email"]
    min_confidentiality: SECRET
    action: BLOCK

  - name: warn_confidential_to_email
    description: "Warn when confidential data flows to email"
    source_tools: ["*"]
    dest_tools: ["email"]
    min_confidentiality: CONFIDENTIAL
    action: WARN

  - name: block_untrusted_to_filesystem
    description: "Low-integrity data cannot write to filesystem"
    source_tools: ["web_fetch"]
    dest_tools: ["filesystem"]
    max_integrity: LOW
    action: BLOCK

  - name: block_untrusted_to_database
    description: "Low-integrity data cannot write to database"
    source_tools: ["web_fetch"]
    dest_tools: ["database"]
    max_integrity: LOW
    action: BLOCK
```

### `policies/strict_policy.yaml`

```yaml
version: "1.0"
description: "Strict policy — blocks any flow from higher to lower confidentiality"

tool_labels:
  filesystem:  { confidentiality: SECRET,       integrity: HIGH }
  database:    { confidentiality: SECRET,        integrity: HIGH }
  web_fetch:   { confidentiality: PUBLIC,        integrity: LOW  }
  email:       { confidentiality: INTERNAL,      integrity: MEDIUM }

rules:
  - name: block_all_to_web
    description: "Nothing flows to web_fetch"
    source_tools: ["*"]
    dest_tools: ["web_fetch"]
    min_confidentiality: INTERNAL
    action: BLOCK

  - name: block_all_to_email
    description: "Nothing confidential flows to email"
    source_tools: ["*"]
    dest_tools: ["email"]
    min_confidentiality: CONFIDENTIAL
    action: BLOCK

  - name: block_all_untrusted_writes
    description: "Untrusted sources cannot write anywhere"
    source_tools: ["web_fetch"]
    dest_tools: ["filesystem", "database", "email"]
    action: BLOCK
```

### `policies/permissive_policy.yaml`

```yaml
version: "1.0"
description: "Permissive policy — only blocks the most obvious violations"

tool_labels:
  filesystem:  { confidentiality: INTERNAL,  integrity: MEDIUM }
  database:    { confidentiality: INTERNAL,   integrity: MEDIUM }
  web_fetch:   { confidentiality: PUBLIC,     integrity: LOW    }
  email:       { confidentiality: PUBLIC,     integrity: LOW    }

rules:
  - name: block_secret_only
    description: "Only block SECRET data from leaving"
    source_tools: ["*"]
    dest_tools: ["web_fetch", "email"]
    min_confidentiality: SECRET
    action: BLOCK
```

---

## Tests to Write

### `tests/test_lattice/test_lattice.py` — critical tests

```python
from flowguard.lattice.lattice import SecurityLattice
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel as C, IntegrityLevel as I

def test_can_flow_public_low_to_public_low():
    assert SecurityLattice.can_flow(
        SecurityLabel(C.PUBLIC, I.LOW), SecurityLabel(C.PUBLIC, I.LOW)
    )

def test_can_flow_blocked_higher_confidentiality():
    # SECRET cannot flow to PUBLIC (BLP violation)
    assert not SecurityLattice.can_flow(
        SecurityLabel(C.SECRET, I.HIGH), SecurityLabel(C.PUBLIC, I.LOW)
    )

def test_can_flow_blocked_lower_integrity():
    # LOW integrity cannot flow to HIGH integrity destination (Biba violation)
    assert not SecurityLattice.can_flow(
        SecurityLabel(C.PUBLIC, I.LOW), SecurityLabel(C.PUBLIC, I.HIGH)
    )

def test_join_takes_max_conf_min_integ():
    a = SecurityLabel(C.CONFIDENTIAL, I.HIGH)
    b = SecurityLabel(C.PUBLIC, I.LOW)
    result = SecurityLattice.join(a, b)
    assert result.confidentiality == C.CONFIDENTIAL
    assert result.integrity == I.LOW

def test_bottom_can_flow_everywhere():
    for label in SecurityLattice.all_labels():
        # BOTTOM (PUBLIC, LOW) should be able to flow anywhere
        # where conf >= PUBLIC and integ <= LOW — only (PUBLIC, LOW) itself
        pass  # implement exhaustive check

def test_top_cannot_flow_anywhere_except_top():
    top = SecurityLattice.TOP
    for label in SecurityLattice.all_labels():
        if label != top:
            assert not SecurityLattice.can_flow(top, label)
```

### `tests/test_policy/test_engine.py` — critical tests

```python
from pathlib import Path
from flowguard.policy.engine import PolicyEngine
from flowguard.policy.types import FlowRequest, Decision
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel as C, IntegrityLevel as I
from datetime import datetime

def make_request(src_tool, dst_tool, src_conf, src_integ, dst_conf, dst_integ):
    return FlowRequest(
        source_tool=src_tool,
        dest_tool=dst_tool,
        source_label=SecurityLabel(src_conf, src_integ),
        dest_label=SecurityLabel(dst_conf, dst_integ),
        session_id="test",
        timestamp=datetime.utcnow(),
    )

def test_exfiltration_is_blocked(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    req = make_request("filesystem", "web_fetch", C.CONFIDENTIAL, I.HIGH, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK

def test_integrity_poison_is_blocked(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    req = make_request("web_fetch", "filesystem", C.PUBLIC, I.LOW, C.CONFIDENTIAL, I.HIGH)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK

def test_safe_flow_is_allowed(default_policy_path):
    engine = PolicyEngine(default_policy_path)
    # PUBLIC LOW -> PUBLIC LOW is always safe
    req = make_request("web_fetch", "web_fetch", C.PUBLIC, I.LOW, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.ALLOW

def test_lattice_block_cannot_be_overridden(permissive_policy_path):
    # Even with a permissive policy, lattice violation is always BLOCK
    engine = PolicyEngine(permissive_policy_path)
    req = make_request("filesystem", "web_fetch", C.SECRET, I.HIGH, C.PUBLIC, I.LOW)
    decision = engine.evaluate(req)
    assert decision.decision == Decision.BLOCK
```

### `tests/conftest.py`

```python
import pytest
from pathlib import Path

@pytest.fixture
def default_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "default_policy.yaml"

@pytest.fixture
def strict_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "strict_policy.yaml"

@pytest.fixture
def permissive_policy_path() -> Path:
    return Path(__file__).parent.parent / "policies" / "permissive_policy.yaml"
```

---

## Interface to Other Components

The teammate building the Runtime Monitor (Phase 2) needs exactly two things from Phase 1:

```python
# 1. SecurityLabel — to attach labels to tainted data
from flowguard.lattice.labels import SecurityLabel
from flowguard.lattice.levels import ConfidentialityLevel, IntegrityLevel
label = SecurityLabel(ConfidentialityLevel.CONFIDENTIAL, IntegrityLevel.HIGH)

# 2. PolicyEngine — to make enforcement decisions
from flowguard.policy.engine import PolicyEngine
from flowguard.policy.types import FlowRequest, Decision
engine = PolicyEngine(Path("policies/default_policy.yaml"))
decision = engine.evaluate(request)
if decision.decision == Decision.BLOCK:
    ...
```

That's the full contract. Phase 2 does not need to know about `PolicyRuleSet`, `PolicyLoader`, or the lattice internals.

---

## Definition of Done

- [ ] `pip install -e ".[dev]"` succeeds
- [ ] All 3 policy YAML files load without error
- [ ] `pytest tests/test_lattice/` passes
- [ ] `pytest tests/test_policy/` passes
- [ ] `engine.evaluate()` correctly blocks the exfiltration and integrity poison test cases above
- [ ] `engine.evaluate()` returns BLOCK for any lattice violation even under `permissive_policy.yaml`
