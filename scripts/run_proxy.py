"""
Entry point: launches the FlowGuard proxy with all mock backend tool servers.

Architecture:
    Simulated LLM --(stdio MCP)--> FlowGuardProxy --(in-memory MCP)--> Mock Tool Servers

Usage:
    python scripts/run_proxy.py
    python scripts/run_proxy.py --policy policies/strict_policy.yaml
    python scripts/run_proxy.py --no-enforce   # disable enforcement (baseline mode)
"""

import argparse
import asyncio
from pathlib import Path

import anyio
from mcp.shared.memory import create_connected_server_and_client_session

# TODO: these imports will work once Phase 1 and Phase 2A are complete
from flowguard.mock_tools.database import create_database_server
from flowguard.mock_tools.email import create_email_server
from flowguard.mock_tools.filesystem import create_filesystem_server
from flowguard.mock_tools.web_fetch import create_web_fetch_server
from flowguard.monitor.proxy import FlowGuardProxy


async def main(policy_path: Path, enforcement_enabled: bool) -> None:
    proxy = FlowGuardProxy(
        policy_path=policy_path,
        session_id="run-proxy-session",
        enforcement_enabled=enforcement_enabled,
    )

    backends = {
        "filesystem": create_filesystem_server(),
        "web_fetch": create_web_fetch_server(),
        "database": create_database_server(),
        "email": create_email_server(),
    }

    # Connect each mock backend to the proxy via in-memory transport.
    # All sessions must stay alive for the proxy's full lifetime, so we
    # open them all before starting the proxy server.
    async with (
        create_connected_server_and_client_session(backends["filesystem"]) as fs_session,
        create_connected_server_and_client_session(backends["web_fetch"]) as web_session,
        create_connected_server_and_client_session(backends["database"]) as db_session,
        create_connected_server_and_client_session(backends["email"]) as email_session,
    ):
        await proxy.register_backend("filesystem", fs_session)
        await proxy.register_backend("web_fetch", web_session)
        await proxy.register_backend("database", db_session)
        await proxy.register_backend("email", email_session)

        enforcement_status = "ENABLED" if enforcement_enabled else "DISABLED"
        print(f"FlowGuard proxy started (enforcement: {enforcement_status})")
        print(f"Policy: {policy_path}")
        print("Listening on stdio...")

        await proxy.server.run_async(transport="stdio")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the FlowGuard MCP proxy")
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("policies/default_policy.yaml"),
        help="Path to the policy YAML file",
    )
    parser.add_argument(
        "--no-enforce",
        action="store_true",
        help="Disable enforcement (baseline mode)",
    )
    args = parser.parse_args()

    anyio.run(main, args.policy, not args.no_enforce)
