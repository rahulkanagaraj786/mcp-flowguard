# Phase 2A: Taint Engine — Spec Sheet

**Depends on:** Phase 1 (Policy Engine) must be complete
**Phase 2B depends on:** `ToolCallInterceptor`, `SessionContext`, `StructuredLogger`

---

## Goal

Build the taint tracking and enforcement core. This component sits between Phase 1 (policy decisions) and Phase 2B (MCP proxy). It tracks what data has entered the LLM context, computes the aggregate security label across all tainted data, and enforces policy decisions at every tool boundary.

No MCP SDK knowledge required — this is pure Python.

---

## Files to Implement

### `src/flowguard/logging/structured.py`

Define a `StructuredLogger` class that logs all flow decisions and taint events as structured JSON.

Constructor takes a `session_id: str` and an optional `log_file: str`. If a log file path is given, write events there; otherwise write to stdout.

Methods:
- `log_decision(decision: FlowDecision)` — logs a flow decision event with source/dest tool, labels, decision, reason, matched rule, and timestamp
- `log_taint(tool_name: str, label: SecurityLabel, content_preview: str)` — logs when data is assigned a label
- `log_warning(message: str)` — logs a warning string
- `get_events() -> list[dict]` — returns all events logged in this session (used by the attack runner to analyze results)

Each event should be a dict with a `type` field (`"flow_decision"` or `"taint_assignment"` or `"warning"`), `session_id`, `timestamp` (ISO format), and the relevant fields for that event type.

---

### `src/flowguard/monitor/context.py`

Define two classes: `TaintedData` and `SessionContext`.

**`TaintedData`** is a dataclass with:
- `content_hash: str` — SHA-256 of the raw content string (do not store raw content)
- `label: SecurityLabel`
- `source_tool: str`
- `timestamp: datetime`
- `content_preview: str` — first 100 characters, for logging only

**`SessionContext`** tracks the security state of a single LLM session:
- `session_id: str`
- `tainted_data: dict[str, TaintedData]` — maps content_hash to TaintedData
- `current_context_label: SecurityLabel` — starts at `SecurityLattice.BOTTOM`
- `flow_log: list[dict]` — audit log of all flow events

Methods:
- `add_taint(data: TaintedData)` — adds a tainted data item and recomputes the aggregate context label
- `get_context_label() -> SecurityLabel` — returns `current_context_label`
- `record_flow(source_tool, dest_tool, label, decision, reason)` — appends a flow event to `flow_log`
- `clear()` — resets all tainted data and resets `current_context_label` to BOTTOM

The aggregate context label is the JOIN of all individual data labels. When new data is added, recompute it by joining all stored labels from scratch. This models the fact that the LLM may embed any piece of its context into any tool call argument.

---

### `src/flowguard/monitor/labeler.py`

Define a `LabelAssigner` class responsible for assigning a `SecurityLabel` to data returned by a tool.

Constructor takes:
- `tool_labels: dict[str, SecurityLabel]` — static mapping from tool name to base label
- `content_rules: list[dict]` — optional list of regex-based upgrade rules, each with a `pattern`, `confidentiality`, and `integrity` field

Methods:
- `assign_label(tool_name: str, content: str) -> SecurityLabel` — assigns a label to tool output
- `get_tool_clearance(tool_name: str) -> SecurityLabel` — returns the clearance level of a destination tool (used by the interceptor as the `dest_label` in a FlowRequest)
- `from_policy_file(path: Path) -> LabelAssigner` — class method that builds a LabelAssigner from the `tool_labels` section of a policy YAML

Label assignment logic:
1. Start with the static label for the tool. If the tool has no configured label, default to `BOTTOM`.
2. Check each content rule's regex against the content string (case-insensitive). If matched, JOIN the current label with the rule's label.
3. Content rules can only upgrade labels (via join), never downgrade. This is a security invariant.

Examples of content rules: a regex for `SSN|social.security` upgrades to (CONFIDENTIAL, HIGH); a regex for `SECRET_API_KEY|password` upgrades to (SECRET, HIGH).

---

### `src/flowguard/monitor/propagation.py`

Define a `TaintPropagator` class that manages taint flow into and out of the `SessionContext`.

Constructor takes a `SessionContext`.

Methods:
- `on_tool_output(tool_name: str, content: str, label: SecurityLabel)` — called after a tool returns data. Hashes the content with SHA-256, creates a `TaintedData` entry, and calls `context.add_taint()`.
- `get_flow_source_label() -> SecurityLabel` — returns the current aggregate context label. This is the "source" label used in a `FlowRequest` when the LLM makes an outgoing tool call, because the LLM may route any data currently in its context to that tool.
- `reset()` — calls `context.clear()`

Key insight: the source label for any outgoing tool call is not just the label of the most recent tool output — it is the aggregate label of everything currently in the LLM's context. This is what makes taint tracking meaningful.

---

### `src/flowguard/monitor/interceptor.py`

Define a `ToolCallInterceptor` class. This is the core enforcement point that satisfies the reference monitor requirement of complete mediation — every tool call must pass through it.

Constructor takes:
- `engine: PolicyEngine`
- `labeler: LabelAssigner`
- `context: SessionContext`
- `logger: StructuredLogger`

Internally creates a `TaintPropagator` from the context.

Methods:
- `pre_call_check(dest_tool: str) -> FlowDecision` — called before a tool is invoked. Gets the current aggregate context label from the propagator (this is the source label), gets the destination tool's clearance from the labeler (this is the dest label), builds a `FlowRequest` with `source_tool="llm_context"`, calls `engine.evaluate()`, logs the decision, records the flow in the context, and returns the decision.
- `post_call_process(tool_name: str, content: str) -> SecurityLabel` — called after a tool returns data. Calls `labeler.assign_label()` to get the label, calls `propagator.on_tool_output()` to propagate the taint, logs the taint assignment, and returns the label.

The interceptor is stateless itself — all state lives in the `SessionContext`. This makes it safe to create multiple interceptors sharing the same context.

---

## Tests to Write

### `tests/test_monitor/test_context.py`
- Adding taint updates the aggregate context label correctly
- Adding two items: label becomes JOIN of both
- `clear()` resets context label to BOTTOM
- `record_flow()` appends to flow_log

### `tests/test_monitor/test_labeler.py`
- Static tool label returned correctly
- Unknown tool returns BOTTOM
- Content rule matching upgrades label via join
- Content rule cannot downgrade a label (if base label is higher than the rule's label, the result stays at the base)
- `from_policy_file()` correctly parses tool_labels from YAML

### `tests/test_monitor/test_propagation.py`
- After two tool outputs, `get_flow_source_label()` returns JOIN of both labels
- `reset()` resets the context
- SHA-256 hash is consistent for same content

### `tests/test_monitor/test_interceptor.py`
- `pre_call_check()` returns BLOCK when context label cannot flow to dest tool
- `pre_call_check()` returns ALLOW when context is clean (BOTTOM)
- `post_call_process()` correctly taints the context after a tool call
- Sequence: clean context -> read SECRET file -> `pre_call_check(web_fetch)` returns BLOCK

### `tests/logging/test_structured.py`
- `log_decision()` appends a `flow_decision` event with correct fields
- `log_taint()` appends a `taint_assignment` event
- `get_events()` returns all logged events in order

---

## Interface to Phase 2B

Phase 2B (the MCP proxy) needs exactly one thing from Phase 2A:

```
ToolCallInterceptor(engine, labeler, context, logger)
  .pre_call_check(dest_tool)   -> FlowDecision
  .post_call_process(tool_name, content) -> SecurityLabel
```

Phase 2B creates the `PolicyEngine`, `LabelAssigner`, `SessionContext`, and `StructuredLogger`, wires them together into a `ToolCallInterceptor`, and calls the two methods around every backend tool call.

---

## Definition of Done

- [ ] `pytest tests/test_monitor/` passes
- [ ] Sequence test passes: clean context -> filesystem read (SECRET) -> `pre_call_check("web_fetch")` returns BLOCK
- [ ] Sequence test passes: clean context -> web_fetch read (PUBLIC/LOW) -> `pre_call_check("filesystem")` returns BLOCK (Biba)
- [ ] `get_events()` returns structured log entries for both the taint assignment and the block decision
