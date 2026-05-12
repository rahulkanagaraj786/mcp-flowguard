# MCP FlowGuard

A runtime information flow enforcement system for MCP-based LLM pipelines. FlowGuard labels data entering the LLM context from tools with confidentiality and integrity levels, intercepts tool calls at runtime, and blocks or flags flows that violate a declared policy. The policy model is grounded in Bell-LaPadula (BLP) and Biba formalisms, targeting the exfiltration and integrity poisoning attack classes that arise from unrestricted MCP tool chaining.

## Architecture

```
LLM Client  <--MCP-->  FlowGuardProxy  <--MCP-->  Backend Tool Servers
                        (enforcement)              (filesystem, web_fetch,
                                                    database, email)
```

FlowGuard sits as an MCP proxy between the LLM and its tools. Every tool call passes through a pre-call policy check (can the current tainted context flow to this destination?) and a post-call taint step (label the output and propagate it into the session context).

## Components

### Policy Engine (`src/flowguard/lattice/`, `src/flowguard/policy/`)

- **2D security lattice** combining BLP (confidentiality) and Biba (integrity):
  - `ConfidentialityLevel`: PUBLIC < INTERNAL < CONFIDENTIAL < SECRET
  - `IntegrityLevel`: LOW < MEDIUM < HIGH
- **`SecurityLabel`**: a `(confidentiality, integrity)` pair. Flow `A -> B` is allowed only when `A.confidentiality <= B.confidentiality` AND `A.integrity >= B.integrity`.
- **`PolicyEngine`**: evaluates `FlowRequest` against explicit YAML rules and the lattice. Rule precedence: BLOCK > WARN > ALLOW. The lattice constraint cannot be overridden by any rule.

### Taint Monitor (`src/flowguard/monitor/`)

- **`SessionContext`**: tracks all tainted data in the LLM context; maintains the aggregate label as the lattice JOIN of all individual labels.
- **`LabelAssigner`**: maps tool names to base labels (from policy file); content-based regex rules can only upgrade labels, never downgrade.
- **`TaintPropagator`**: on each tool output, hashes the content, creates a `TaintedData` record, and adds it to the session context.
- **`ToolCallInterceptor`**: `pre_call_check` enforces policy before forwarding; `post_call_process` taints the context after receiving output.
- **`FlowGuardProxy`**: discovers tools from backend MCP servers at startup, re-exposes them with a `server__tool` naming scheme, and routes all calls through the interceptor.

### Mock Tool Servers (`src/flowguard/mock_tools/`)

Standalone FastMCP servers with canned responses for attack simulation:

| Server | Tools | Label |
|---|---|---|
| `filesystem` | `read_file`, `write_file`, `list_files` | CONFIDENTIAL / HIGH |
| `web_fetch` | `fetch_url`, `post_data` | PUBLIC / LOW |
| `database` | `query`, `insert` | CONFIDENTIAL / HIGH |
| `email` | `send_email`, `read_inbox` | INTERNAL / MEDIUM |

### Policies (`policies/`)

Three policy files covering different enforcement levels:

- `default_policy.yaml` — blocks obvious exfiltration and integrity poisoning
- `strict_policy.yaml` — blocks all outbound flows from confidential sources
- `permissive_policy.yaml` — only blocks SECRET-level exfiltration

## Setup

```bash
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

All 67 tests cover the lattice, policy engine, taint monitor components, mock servers, and proxy integration scenarios.

## Running the Proxy

```bash
python scripts/run_proxy.py
# or with options:
python scripts/run_proxy.py --policy policies/strict_policy.yaml --no-enforce
```

## Attack Scenarios (Phase 3 — in progress)

The following scenarios will be automated in `src/flowguard/attacks/`:

1. **Exfiltration**: Read a SECRET file, then POST to an attacker URL. FlowGuard blocks the outbound call.
2. **Cross-tool taint**: Query PII from the database, then send an email. FlowGuard warns or blocks.
3. **Integrity poisoning**: Fetch untrusted web content, then write to the filesystem. FlowGuard blocks the write.
4. **Policy misconfiguration**: Show that a permissive policy allows attacks that the strict policy blocks.

## Project Status

| Phase | Description | Status |
|---|---|---|
| 1 | Policy engine (lattice, rules, loader) | Done |
| 2A | Taint monitor (context, labeler, propagator, interceptor) | Done |
| 2B | MCP proxy + mock tool servers | Done |
| 3 | Attack runner + report generation | In progress |
