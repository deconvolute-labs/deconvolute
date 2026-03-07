import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deconvolute.models.observability import AccessEvent, DiscoveryEvent
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)


@pytest.fixture
def mock_mcp_modules():
    """
    Patches mcp modules in sys.modules and ensures deconvolute.clients.mcp uses them.
    """
    mcp_mock = MagicMock()
    mcp_types_mock = MagicMock()
    mcp_mock.types = mcp_types_mock

    # Needs to be able to be imported
    with patch.dict("sys.modules", {"mcp": mcp_mock, "mcp.types": mcp_types_mock}):
        # Reload to bind to mocks
        if "deconvolute.clients.mcp" in sys.modules:
            import importlib

            import deconvolute.clients.mcp

            importlib.reload(deconvolute.clients.mcp)
        else:
            import deconvolute.clients.mcp

        yield mcp_types_mock


@pytest.fixture
def proxy(mock_mcp_modules):
    from deconvolute.clients.mcp import MCPProxy

    session = MagicMock()
    session.list_tools = AsyncMock()
    session.call_tool = AsyncMock()

    # Mock server_info to avoid validation errors
    session.server_info = MagicMock()
    session.server_info.name = "test_server"
    session.server_info.version = "1.0.0"
    if hasattr(session, "serverInfo"):
        del session.serverInfo

    firewall = MagicMock()
    return MCPProxy(session, firewall)


@pytest.mark.asyncio
async def test_list_tools_logs_discovery(proxy):
    # Mock backend
    mock_backend = MagicMock()
    with patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend):
        # Setup tools
        tool_a = MagicMock(name="ToolA")
        tool_a.name = "allowed"
        tool_a.description = "Allowed tool"
        tool_a.inputSchema = {}

        tool_b = MagicMock(name="ToolB")
        tool_b.name = "blocked"
        tool_b.description = "Blocked tool"
        tool_b.inputSchema = {}

        # Mock session
        initial_result = MagicMock()
        initial_result.tools = [tool_a, tool_b]
        initial_result.model_copy.side_effect = lambda update: update
        proxy._session.list_tools.return_value = initial_result

        # Mock firewall
        proxy._firewall.check_tool_list.return_value = [{"name": "allowed"}]
        mock_snapshot = MagicMock()
        mock_snapshot.definition_hash = "hash_123"
        proxy._firewall.registry.get.return_value = mock_snapshot

        # Execute
        await proxy.list_tools()

        # Verify
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        event = DiscoveryEvent.model_validate(event_dict)
        assert event.tools_found_count == 2
        assert event.tools_allowed_count == 1
        assert any(t.name == "allowed" for t in event.tools_allowed)
        assert any(t.name == "blocked" for t in event.tools_blocked)


@pytest.mark.asyncio
async def test_call_tool_logs_access_safe(proxy):
    mock_backend = MagicMock()
    with patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend):
        # Setup
        proxy._firewall.check_tool_call.return_value = SecurityResult(
            status=SecurityStatus.SAFE, component=SecurityComponent.FIREWALL
        )
        proxy._session.call_tool.return_value = "success"

        # Execute
        await proxy.call_tool("safe_tool")

        # Verify
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        event = AccessEvent.model_validate(event_dict)
        assert event.tool_name == "safe_tool"
        assert event.status == SecurityStatus.SAFE
        assert event.reason == "policy_allow"


@pytest.mark.asyncio
async def test_call_tool_logs_access_unsafe(proxy, mock_mcp_modules):
    mock_backend = MagicMock()
    with patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend):
        # Setup
        proxy._firewall.check_tool_call.return_value = SecurityResult(
            status=SecurityStatus.UNSAFE,
            component=SecurityComponent.FIREWALL,
            metadata={"reason": "bad_actor"},
        )

        # Mock CallToolResult
        types_mock = mock_mcp_modules
        types_mock.CallToolResult.return_value = MagicMock(isError=True)

        # Execute
        await proxy.call_tool("unsafe_tool")

        # Verify
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        event = AccessEvent.model_validate(event_dict)
        assert event.tool_name == "unsafe_tool"
        assert event.status == SecurityStatus.UNSAFE
        assert event.reason == "bad_actor"


@pytest.mark.asyncio
async def test_call_tool_logs_integrity_violation(proxy, mock_mcp_modules):
    """Test the rug pull scenario where a tool vanishes."""
    # Enable strict mode
    proxy._integrity_mode = "strict"

    mock_backend = MagicMock()
    with patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend):
        # Mock initial list_tools to return EMPTY list (tool vanished)
        empty_result = MagicMock()
        empty_result.tools = []
        proxy._session.list_tools.return_value = empty_result

        # Mock CallToolResult
        types_mock = mock_mcp_modules
        types_mock.CallToolResult.return_value = MagicMock(isError=True)

        # Execute
        await proxy.call_tool("vanished_tool")

        # Verify
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        event = AccessEvent.model_validate(event_dict)
        assert event.tool_name == "vanished_tool"
        assert event.status == SecurityStatus.UNSAFE
        assert event.reason == "integrity_violation"
        assert event.metadata["reason"] == "tool_vanished"


@pytest.mark.asyncio
async def test_call_tool_logs_strict_error(proxy, mock_mcp_modules):
    """Test that system errors during strict check are logged to audit."""
    # Enable strict mode
    proxy._integrity_mode = "strict"

    mock_backend = MagicMock()
    with patch("deconvolute.clients.mcp.get_backend", return_value=mock_backend):
        # Mock list_tools to raise a network/system error
        proxy._session.list_tools.side_effect = Exception("Network Down")

        # Mock CallToolResult
        types_mock = mock_mcp_modules
        types_mock.CallToolResult.return_value = MagicMock(isError=True)

        # Execute
        await proxy.call_tool("any_tool")

        # Verify
        mock_backend.log_event.assert_called_once()
        event_dict = mock_backend.log_event.call_args[0][1]
        event = AccessEvent.model_validate(event_dict)
        assert event.tool_name == "any_tool"
        assert event.status == SecurityStatus.UNSAFE
        assert event.reason == "integrity_check_error"
        assert event.metadata["error"] == "Network Down"
