from pathlib import Path
from typing import Any

from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent, Tool as MCPTool

from flowguard.lattice.labels import SecurityLabel
from flowguard.logging.structured import StructuredLogger
from flowguard.monitor.context import SessionContext
from flowguard.monitor.interceptor import ToolCallInterceptor
from flowguard.monitor.labeler import LabelAssigner
from flowguard.policy.engine import PolicyEngine
from flowguard.policy.types import Decision


def _make_proxy_handler(proxy: "FlowGuardProxy", qualified_name: str):
    async def handler(**kwargs: Any) -> str:
        return await proxy._handle_tool_call(qualified_name, kwargs)
    return handler


class FlowGuardProxy:
    """
    MCP proxy server that mediates all tool calls between an LLM client
    and backend tool servers.

    Architecture:
        LLM Client <--MCP--> FlowGuardProxy <--MCP--> Backend Tool Servers

    Every tool call is intercepted, checked against the policy engine,
    and either forwarded or blocked before the backend is contacted.
    """

    def __init__(
        self,
        policy_path: Path,
        session_id: str = "default",
        enforcement_enabled: bool = True,
    ) -> None:
        self._enforcement_enabled = enforcement_enabled
        self._session_id = session_id

        engine = PolicyEngine(policy_path)
        labeler = LabelAssigner.from_policy_file(policy_path)
        context = SessionContext(session_id=session_id)
        logger = StructuredLogger(session_id=session_id)

        self._context = context
        self._logger = logger
        self._interceptor = ToolCallInterceptor(
            engine=engine,
            labeler=labeler,
            context=context,
            logger=logger,
        )

        # tool qualified_name -> (client_session, original_tool_name)
        self._backends: dict[str, tuple[ClientSession, str]] = {}

        self._server = FastMCP(name="flowguard-proxy")

    async def register_backend(
        self, server_name: str, client_session: ClientSession
    ) -> None:
        """Connect to a backend MCP server and re-expose all its tools."""
        tools_result = await client_session.list_tools()
        for tool in tools_result.tools:
            qualified_name = f"{server_name}__{tool.name}"
            self._backends[qualified_name] = (client_session, tool.name)
            self._server.add_tool(
                _make_proxy_handler(self, qualified_name),
                name=qualified_name,
                description=tool.description or "",
            )

    async def _handle_tool_call(
        self, qualified_name: str, arguments: dict[str, Any]
    ) -> str:
        """Core interception logic for every tool call."""
        tool_category = qualified_name.split("__")[0]

        if self._enforcement_enabled:
            decision = self._interceptor.pre_call_check(tool_category)
            if decision.decision == Decision.BLOCK:
                return f"[BLOCKED] {decision.reason}"
            if decision.decision == Decision.WARN:
                self._logger.log_warning(
                    f"Flow warning on call to {tool_category}: {decision.reason}"
                )

        client_session, original_tool_name = self._backends[qualified_name]
        result = await client_session.call_tool(original_tool_name, arguments)
        content_text = self._extract_text(result.content)

        if self._enforcement_enabled:
            self._interceptor.post_call_process(tool_category, content_text)

        return content_text

    @staticmethod
    def _extract_text(content_blocks: list) -> str:
        return "\n".join(
            block.text for block in content_blocks if isinstance(block, TextContent)
        )

    @property
    def server(self) -> FastMCP:
        return self._server

    def get_flow_log(self) -> list[dict]:
        return self._context.flow_log

    def get_context_label(self) -> SecurityLabel:
        return self._context.get_context_label()

    def reset_context(self) -> None:
        self._context.clear()
