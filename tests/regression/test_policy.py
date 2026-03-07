from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import mcp.types as types
import pytest
from mcp.server import Server
from mcp.shared.memory import create_connected_server_and_client_session

from deconvolute.clients.mcp import MCPProxy
from deconvolute.core.firewall import MCPFirewall
from deconvolute.core.policy import PolicyLoader
from deconvolute.errors import TransportSpoofingError
from deconvolute.models.security import SecurityStatus, SSEOrigin, StdioOrigin


@pytest.fixture
def mock_firewall() -> MCPFirewall:
    """
    Provides a firewall instance loaded with the local regression policy.
    """
    policy_path = Path(__file__).parent / "policy.yaml"
    parsed_policy = PolicyLoader.load(str(policy_path))
    firewall = MCPFirewall(policy=parsed_policy)
    return firewall


@pytest.fixture
def mcp_server() -> Server:
    """
    Sets up a lightweight, in-memory MCP server.
    """
    app = Server("test-server")

    @app.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        raw_tools = [
            {
                "name": "test_tool",
                "description": "A simple test tool",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            },
            {
                "name": "blocked_tool",
                "description": "A blocked tool",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "read_file",
                "description": "Reads a file from the disk",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        ]
        return [types.Tool.model_validate(t) for t in raw_tools]

    @app.call_tool()  # type: ignore[untyped-decorator]
    async def call_tool(
        name: str, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        if name == "test_tool":
            return [types.TextContent(type="text", text="Echo")]
        if name == "blocked_tool":
            return [types.TextContent(type="text", text="Should not reach here")]
        if name == "read_file":
            return [
                types.TextContent(
                    type="text", text=f"Contents of {arguments.get('path')}"
                )
            ]
        raise ValueError(f"Unknown tool: {name}")

    return app


@pytest.mark.anyio
async def test_payload_inspection_cel_conditions(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that CEL conditions correctly inspect arguments and block execution.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)
        await proxy.initialize()

        # We must perform discovery first so the firewall registers the tool's
        # existence!
        await proxy.list_tools()

        # Test 1: Safe path (should pass the CEL condition and hit the server)
        safe_result = await proxy.call_tool("read_file", arguments={"path": "data.txt"})
        assert (
            getattr(safe_result, "isError", getattr(safe_result, "is_error", False))
            is False
        )
        assert isinstance(safe_result.content[0], types.TextContent)
        assert "Contents of data.txt" in safe_result.content[0].text

        # Test 2: Malicious path (should fail the CEL condition and return a synthetic
        # block)
        evil_result = await proxy.call_tool(
            "read_file", arguments={"path": "/etc/passwd"}
        )
        assert (
            getattr(evil_result, "isError", getattr(evil_result, "is_error", False))
            is True
        )
        assert isinstance(evil_result.content[0], types.TextContent)
        assert "Security Violation" in evil_result.content[0].text


@pytest.mark.anyio
async def test_transport_spoofing_prevention(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that a mismatched transport origin triggers a TransportSpoofingError.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        # The policy requires 'stdio', but we forcefully inject an 'sse' origin
        evil_origin = SSEOrigin(type="sse", url="https://evil.local/sse")

        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=evil_origin)

        # When initialize is called, the proxy extracts the name 'test-server',
        # passes the evil_origin to the firewall, and the firewall rejects it.
        with pytest.raises(TransportSpoofingError) as exc_info:
            await proxy.initialize()

        assert "Transport type mismatch" in str(exc_info.value)
        assert "test-server" in str(exc_info.value)


@pytest.mark.anyio
async def test_observability_hook_dispatch(
    mcp_server: Server, mock_firewall: MCPFirewall, mocker: Any
) -> None:
    """
    Validates that the proxy correctly dispatches telemetry events to the configured
    backend.
    """

    mock_backend = MagicMock()
    mocker.patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend)

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)
        await proxy.initialize()

        # Trigger Discovery
        await proxy.list_tools()

        # Verify log_event was called
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        from deconvolute.models.observability import DiscoveryEvent

        discovery_event = DiscoveryEvent.model_validate(event_dict)
        assert discovery_event.tools_found_count == 3
        assert discovery_event.tools_allowed_count == 2

        # We manually register the blocked tool to bypass the hallucination/integrity
        # check so we can specifically test the Policy block telemetry hook.
        mock_firewall.registry.register(
            {
                "name": "blocked_tool",
                "description": "A blocked tool",
                "input_schema": {"type": "object", "properties": {}},
            }
        )

        # Trigger a blocked execution
        await proxy.call_tool("blocked_tool", arguments={})

        # Verify log_event was called again
        assert mock_backend.log_event.call_count == 2
        event_dict = mock_backend.log_event.call_args[0][1]
        from deconvolute.models.observability import AccessEvent

        access_event = AccessEvent.model_validate(event_dict)
        assert access_event.tool_name == "blocked_tool"
        assert access_event.status == SecurityStatus.UNSAFE
        assert access_event.reason == "Policy violation"


@pytest.mark.anyio
async def test_unregistered_tool_fails_integrity_check(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that calling a tool without discovering it first triggers an integrity
    block.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)
        await proxy.initialize()

        # We intentionally SKIP calling `await proxy.list_tools()` here.
        # The proxy's SessionRegistry remains empty.

        # We try to call 'read_file', which is a valid tool on the server and allowed
        # by policy, but the proxy doesn't know about it yet.
        result = await proxy.call_tool("read_file", arguments={"path": "data.txt"})

        # Verify the firewall blocks it at the integrity phase
        assert getattr(result, "isError", getattr(result, "is_error", False)) is True
        assert len(result.content) == 1
        assert isinstance(result.content[0], types.TextContent)
        assert "integrity check" in result.content[0].text.lower()
        assert "not registered" in result.content[0].text.lower()
