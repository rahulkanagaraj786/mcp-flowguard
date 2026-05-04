# Phase 1: Policy Engine — Spec Sheet

**Depends on:** Nothing (pure Python, no MCP SDK needed)
**Other components depend on:** `SecurityLabel`, `PolicyEngine.evaluate()`

---

## Goal

Build the theoretical core of FlowGuard: a 2D security lattice combining Bell-LaPadula (confidentiality) and Biba (integrity), a YAML-based policy DSL, and a decision engine that takes a flow request and returns ALLOW / WARN / BLOCK.

Install with: `pip install -e ".[dev]"`

---

## Files to Implement

### `src/flowguard/lattice/levels.py`

Define two `IntEnum` classes: `ConfidentialityLevel` (PUBLIC=0, INTERNAL=1, CONFIDENTIAL=2, SECRET=3) and `IntegrityLevel` (LOW=0, MEDIUM=1, HIGH=2).

Use `IntEnum` so that comparison operators (`<=`, `>=`) work natively, mapping directly to the lattice partial order.

---

### `src/flowguard/lattice/labels.py`

Define a `SecurityLabel` frozen dataclass with two fields: `confidentiality: ConfidentialityLevel` and `integrity: IntegrityLevel`.

- `dominates(other)` — returns True if self >= other in both dimensions
- `__repr__` — returns `(CONFIDENTIAL, HIGH)` style string

Use `frozen=True` so labels are immutable and hashable (required for dict keys in taint tracking). Use `order=False` to prevent lexicographic auto-ordering which would be wrong for a 2D lattice.

---

### `src/flowguard/lattice/lattice.py`

Define a `SecurityLattice` class with static methods only:

- `join(a, b)` — least upper bound: `max(confidentiality)`, `min(integrity)`. Used when the LLM absorbs outputs from two tools; the result must be as restrictive as the worst input on each dimension.
- `meet(a, b)` — greatest lower bound: `min(confidentiality)`, `max(integrity)`
- `can_flow(source, dest)` — BLP + Biba combined check: `source.conf <= dest.conf AND source.integ >= dest.integ`
- Constants: `BOTTOM = (PUBLIC, LOW)`, `TOP = (SECRET, HIGH)`

---

### `src/flowguard/policy/types.py`

Define the core data structures:

- `Decision` (str Enum): ALLOW, WARN, BLOCK
- `FlowRequest` (frozen dataclass): source_tool, dest_tool, source_label, dest_label, session_id, timestamp
- `FlowDecision` (dataclass): decision, request, reason, matched_rule, timestamp
- `PolicyRule` (dataclass): name, source_tools, dest_tools, action, description, min_confidentiality, max_confidentiality, min_integrity, max_integrity. The `source_tools` and `dest_tools` fields are `list[str]` where `["*"]` means any tool. The min/max fields are optional strings like `"CONFIDENTIAL"` that trigger the rule when the source label meets the condition.

---

### `src/flowguard/policy/loader.py`

Define a `PolicyLoader` class with a static `load(path: Path)` method that parses a YAML policy file and returns a tuple of `(list[PolicyRule], dict)` where the dict contains raw tool label mappings like `{"filesystem": {"confidentiality": "CONFIDENTIAL", "integrity": "HIGH"}}`.

---

### `src/flowguard/policy/dsl.py`

Define a `PolicyRuleSet` class that takes a `list[PolicyRule]` and provides:

- `find_matching_rules(source_tool, dest_tool, source_label)` — returns all rules matching the flow, ordered most-specific first (non-wildcard rules before wildcard rules)
- Internal helpers for matching a tool name against a pattern list and checking label constraints against min/max fields

---

### `src/flowguard/policy/engine.py`

Define a `PolicyEngine` class that loads a policy file on init and exposes:

- `evaluate(FlowRequest) -> FlowDecision` — the main decision function
- `get_tool_label(tool_name) -> SecurityLabel` — returns the configured label for a tool's output

Evaluation order:
1. Lattice check (BLP + Biba) — always applied first, cannot be overridden by any rule. If `can_flow` returns False, immediately return BLOCK.
2. Explicit rules — find all matching rules, take the most restrictive action (BLOCK > WARN > ALLOW)
3. Default — if no rule matches and lattice permits, return ALLOW

---

## Policy Files

Three YAML files to create in `policies/`:

### `default_policy.yaml`
Tool labels: filesystem and database at (CONFIDENTIAL, HIGH), web_fetch at (PUBLIC, LOW), email at (INTERNAL, MEDIUM).

Rules:
- Block CONFIDENTIAL+ data flowing to web_fetch
- Block SECRET data flowing to email
- Warn when CONFIDENTIAL data flows to email
- Block LOW-integrity data (from web_fetch) writing to filesystem or database

### `strict_policy.yaml`
Tool labels: filesystem and database upgraded to (SECRET, HIGH).

Rules: block anything INTERNAL+ from reaching web_fetch, block CONFIDENTIAL+ from reaching email, block all writes from web_fetch to any tool.

### `permissive_policy.yaml`
Tool labels: all tools at lower levels (filesystem/database at INTERNAL/MEDIUM, email at PUBLIC/LOW).

Rules: only block SECRET data from leaving via web_fetch or email.

---

## Tests to Write

### `tests/test_lattice/`
- `test_levels.py` — verify ordering of enum values
- `test_labels.py` — verify `dominates()`, frozen/hashable behavior, repr
- `test_lattice.py` — verify `join`, `meet`, `can_flow` for representative label pairs. Key cases:
  - SECRET cannot flow to PUBLIC (BLP violation)
  - LOW integrity cannot flow to HIGH integrity destination (Biba violation)
  - `join` of (CONFIDENTIAL, HIGH) and (PUBLIC, LOW) produces (CONFIDENTIAL, LOW)
  - TOP cannot flow anywhere except TOP
  - BOTTOM can flow to BOTTOM only (since LOW is the minimum integrity)

### `tests/test_policy/`
- `test_loader.py` — load each YAML file, verify rules and tool labels parsed correctly
- `test_dsl.py` — verify rule matching with wildcards, specificity ordering, label constraint matching
- `test_engine.py` — critical cases:
  - Exfiltration (filesystem CONFIDENTIAL -> web_fetch) is BLOCK
  - Integrity poison (web_fetch LOW -> filesystem HIGH) is BLOCK
  - Safe flow (PUBLIC/LOW -> PUBLIC/LOW) is ALLOW
  - Lattice violation is BLOCK even under `permissive_policy.yaml`

### `tests/conftest.py`
Pytest fixtures returning `Path` objects for each of the three policy files.

---

## Interface to Other Components

The teammate building the Runtime Monitor (Phase 2) needs exactly two things from Phase 1:

1. `SecurityLabel` — to attach labels to tainted data
2. `PolicyEngine.evaluate(FlowRequest) -> FlowDecision` — to make enforcement decisions

Phase 2 does not need to know about `PolicyRuleSet`, `PolicyLoader`, or the lattice internals.

---

## Definition of Done

- [ ] `pip install -e ".[dev]"` succeeds
- [ ] All 3 policy YAML files load without error
- [ ] `pytest tests/test_lattice/` passes
- [ ] `pytest tests/test_policy/` passes
- [ ] `engine.evaluate()` correctly blocks exfiltration and integrity poison cases
- [ ] `engine.evaluate()` returns BLOCK for any lattice violation even under `permissive_policy.yaml`
