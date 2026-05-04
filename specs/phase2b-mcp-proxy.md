# Phase 2B: MCP Proxy + Mock Tools — Spec Sheet

**Depends on:** Phase 1 (Policy Engine) and Phase 2A (Taint Engine) must be complete
**Phase 3 depends on:** `FlowGuardProxy` (specifically `_handle_tool_call` and `get_flow_log`)

---

## Goal

Build the MCP proxy server that sits between the LLM and all tool backends, and the four mock tool servers that simulate real MCP tools. The proxy intercepts every tool call, runs it through the taint engine, and either forwards it to the backend or blocks it. This component requires familiarity with the MCP Python SDK.

Install the MCP SDK: `pip install mcp anyio`

---

## Architecture

```
LLM Client  <--MCP-->  FlowGuardProxy  <--MCP-->  Mock Tool Servers
                        (FastMCP server)            (filesystem, web_fetch,
                                                     database, email)
```

The proxy is itself an MCP server (the LLM connects to it), and also an MCP client (it connects to each backend). All connections use the MCP SDK's in-memory transport so no network or subprocess is needed.

---

## MCP SDK Concepts You Need

- **`FastMCP`** (`mcp.server.fastmcp`) — decorator-based server for defining tools. Use `@server.tool()` to register a tool handler.
- **`ClientSession`** (`mcp.client.session`) — async client session for connecting to a server.
- **In-memory transport** (`mcp.shared.memory`) — connects a client directly to a server in the same process using async streams. Use `create_connected_server_and_client_session` as an async context manager.
- All MCP operations are async. Use `anyio` as the async runtime.

---

## Files to Implement

### `src/flowguard/mock_tools/filesystem.py`

Create a function `create_filesystem_server() -> FastMCP` that returns a FastMCP server named `"filesystem"` with three tools:

- `read_file(path: str) -> str` — returns canned content based on the path. Include at least:
  - `/etc/secrets/api_key.txt` → a string containing `SECRET_API_KEY=sk-abc123...`
  - `/data/employees.csv` → a CSV with SSN and salary fields
  - `/public/readme.txt` → benign public content
  - Any other path → `"File not found: {path}"`
- `write_file(path: str, content: str) -> str` — returns a confirmation string, does not actually write anything
- `list_files(directory: str) -> str` — returns a newline-separated list of the canned file paths

---

### `src/flowguard/mock_tools/web_fetch.py`

Create `create_web_fetch_server() -> FastMCP` with two tools:

- `fetch_url(url: str) -> str` — returns canned responses. Include at least:
  - `https://attacker.com/exfil` → `"Data received. Exfiltration successful."`
  - `https://evil.com/payload` → content with a script injection payload
  - Any other URL → benign news content
- `post_data(url: str, data: str) -> str` — returns `"POST to {url}: 200 OK (sent {len(data)} bytes)"`. This simulates a successful exfiltration endpoint.

---

### `src/flowguard/mock_tools/database.py`

Create `create_database_server() -> FastMCP` with two tools:

- `query(sql: str) -> str` — returns canned results. If the query mentions `employees`, return a CSV with `id, name, email, ssn` rows. Otherwise return an empty result.
- `insert(table: str, data: str) -> str` — returns a confirmation string

---

### `src/flowguard/mock_tools/email.py`

Create `create_email_server() -> FastMCP` with two tools:

- `send_email(to: str, subject: str, body: str) -> str` — returns `"Email sent to {to}: '{subject}' ({len(body)} chars)"`
- `read_inbox() -> str` — returns a canned inbox with two emails, one marked CONFIDENTIAL

---

### `src/flowguard/monitor/proxy.py`

Define a `FlowGuardProxy` class. This is the architectural centerpiece.

Constructor takes:
- `policy_path: Path`
- `session_id: str` — defaults to `"default"`
- `enforcement_enabled: bool` — defaults to `True`. When False, tool calls pass through without any policy checking (used by the attack runner to get baseline results).

On init, the proxy creates a `PolicyEngine`, `LabelAssigner`, `SessionContext`, `StructuredLogger`, and `ToolCallInterceptor`. It also creates an internal `FastMCP` server named `"flowguard-proxy"` that the LLM client will connect to.

**Key methods:**

`register_backend(server_name: str, client_session: ClientSession) -> None` (async)
- Calls `client_session.list_tools()` to discover the backend's tools
- For each tool, generates a qualified name: `"{server_name}__{tool.name}"` (e.g. `"filesystem__read_file"`)
- Registers a proxy handler on the internal FastMCP server for each qualified tool name
- Stores the `(client_session, tool)` pair in an internal `_backends` dict

The proxy handler creation is the trickiest part. Use a factory function (not an inline closure) to avoid Python's late-binding issue:

```
def make_proxy_handler(proxy_instance, qualified_name):
    async def handler(**kwargs):
        return await proxy_instance._handle_tool_call(qualified_name, kwargs)
    return handler
```

Then call `self._server.add_tool(make_proxy_handler(self, qualified_name), name=qualified_name, ...)`.

`_handle_tool_call(tool_name: str, arguments: dict) -> str` (async)
The core logic for every intercepted call:
1. Extract the tool category from the qualified name (the part before `__`, e.g. `"filesystem"`)
2. If `enforcement_enabled`: call `interceptor.pre_call_check(tool_category)`. If BLOCK, return `"[BLOCKED] {reason}"` without forwarding. If WARN, log the warning but continue.
3. Forward to the backend: look up the client_session from `_backends`, call `client_session.call_tool(original_tool_name, arguments)`, extract text from the result's content blocks.
4. If `enforcement_enabled`: call `interceptor.post_call_process(tool_category, content_text)`
5. Return the content text.

**Properties/accessors:**
- `server` — returns the internal FastMCP server instance (used by the test to connect a client)
- `get_flow_log() -> list[dict]` — returns the session context's flow log
- `get_context_label() -> SecurityLabel` — returns the current aggregate context label
- `reset_context()` — clears the session context (called between attack scenario steps)

---

### `scripts/run_proxy.py`

Entry point script that wires everything together using in-memory MCP transports.

Steps:
1. Create a `FlowGuardProxy` with `policies/default_policy.yaml`
2. Create each mock tool server
3. For each mock server, use `create_connected_server_and_client_session` to get a live `ClientSession`
4. Call `proxy.register_backend(name, session)` for each
5. Run the proxy as a stdio MCP server: `proxy.server.run(transport="stdio")`

Use `anyio.run(main)` as the entry point. All backend sessions must be kept alive for the full duration of the proxy's life, so manage them within a single `anyio.create_task_group`.

---

## Tests to Write

### `tests/test_mock_tools/test_mock_servers.py`

For each mock server, use `create_connected_server_and_client_session` to connect a client in-memory and verify:
- `list_tools()` returns the expected tools
- Calling each tool returns the expected canned response
- These tests do not involve the proxy or the policy engine at all

### `tests/test_monitor/test_proxy.py`

Integration tests that wire mock backends to the proxy in-memory. These are the most important tests in the project.

**Setup:** create a `FlowGuardProxy`, create all 4 mock servers, connect each via in-memory transport, call `register_backend` for each.

Test cases:
- `test_proxy_lists_all_tools` — after registering all backends, the proxy exposes tools prefixed with server names (`filesystem__read_file`, etc.)
- `test_exfiltration_blocked` — call `filesystem__read_file` with a secret path, then call `web_fetch__post_data`. Verify the second call returns a string starting with `"[BLOCKED]"`.
- `test_integrity_poison_blocked` — call `web_fetch__fetch_url`, then call `filesystem__write_file`. Verify BLOCK.
- `test_safe_call_allowed` — call `web_fetch__fetch_url` with a benign URL, then call `web_fetch__fetch_url` again. Verify no BLOCK (PUBLIC/LOW -> PUBLIC/LOW is always safe).
- `test_enforcement_disabled` — create a proxy with `enforcement_enabled=False`, run the same exfiltration sequence, verify the call is NOT blocked.
- `test_flow_log_populated` — after running a blocked scenario, verify `get_flow_log()` contains entries with the correct decision and tool names.

---

## Important Implementation Notes

**Late-binding pitfall:** When registering proxy handlers in a loop, always use a factory function. The common mistake is:

```python
# WRONG — all handlers capture the last value of 'name'
for name in tool_names:
    async def handler(**kwargs):
        return await self._handle_tool_call(name, kwargs)  # 'name' is captured by reference
    server.add_tool(handler, name=name)
```

Use the `make_proxy_handler` factory pattern shown above instead.

**In-memory transport lifecycle:** The `create_connected_server_and_client_session` context manager keeps the server running as long as the context is open. In tests, use `async with` for each backend. In `run_proxy.py`, keep all backends alive inside a single task group.

**Extracting text from MCP results:** Tool call results return a list of content blocks. Extract text like this: join the `.text` field of all `TextContent` blocks. Other block types (images, etc.) can be ignored for this project.

**`add_tool` on FastMCP:** FastMCP's `add_tool` method accepts a callable and keyword args for `name` and `description`. The callable's signature determines the input schema FastMCP infers. Using `**kwargs` gives a permissive schema, which is acceptable here since real schema validation happens at the backend.

---

## Definition of Done

- [ ] `pytest tests/test_mock_tools/` passes
- [ ] `pytest tests/test_monitor/test_proxy.py` passes
- [ ] `test_exfiltration_blocked` passes (proxy blocks SECRET filesystem data from reaching web_fetch)
- [ ] `test_integrity_poison_blocked` passes (proxy blocks LOW-integrity web content from reaching filesystem)
- [ ] `test_enforcement_disabled` passes (proxy forwards all calls when enforcement is off)
- [ ] `python scripts/run_proxy.py` starts without errors (can be tested by piping a basic MCP initialize message to it)
