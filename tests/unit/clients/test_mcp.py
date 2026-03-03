import importlib
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
    SSEOrigin,
    StdioOrigin,
)


@pytest.fixture
def mock_mcp_modules():
    """
    Patches mcp modules in sys.modules and ensures deconvolute.clients.mcp uses them.
    """
    mcp_mock = MagicMock()
    mcp_types_mock = MagicMock()
    # Link them so import mcp; mcp.types is the same as import mcp.types
    mcp_mock.types = mcp_types_mock

    with patch.dict("sys.modules", {"mcp": mcp_mock, "mcp.types": mcp_types_mock}):
        # We must ensure deconvolute.clients.mcp is loaded with these mocks
        if "deconvolute.clients.mcp" in sys.modules:
            import deconvolute.clients.mcp

            importlib.reload(deconvolute.clients.mcp)
        else:
            import deconvolute.clients.mcp

        yield mcp_types_mock


@pytest.fixture
def proxy(mock_mcp_modules, mock_session, mock_firewall):
    # Import MCPProxy here, so we get the class defined during the patch validity
    from deconvolute.clients.mcp import MCPProxy

    return MCPProxy(mock_session, mock_firewall)


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.list_tools = AsyncMock()
    session.call_tool = AsyncMock()

    # Mock server_info to avoid validation errors
    session.server_info = MagicMock()
    session.server_info.name = "test_server"
    session.server_info.version = "1.0.0"
    if hasattr(session, "serverInfo"):
        del session.serverInfo

    return session


@pytest.fixture
def mock_firewall():
    firewall = MagicMock()
    return firewall


@pytest.mark.asyncio
async def test_list_tools_filtering_success(proxy, mock_session, mock_firewall):
    # Setup mock tools
    tool_a = MagicMock(name="Tool_a")
    tool_a.name = "allowed_tool"
    tool_a.description = "Allowed Tool Description"
    tool_a.input_schema = {"type": "object"}

    tool_b = MagicMock(name="Tool_b")
    tool_b.name = "blocked_tool"
    tool_b.description = "Blocked Tool Description"
    tool_b.input_schema = {"type": "object"}

    # Mock session response
    initial_result = MagicMock()
    initial_result.tools = [tool_a, tool_b]

    # Configure model_copy to return a new mock with the updated tools
    def side_effect_model_copy(update):
        new_result = MagicMock()
        new_result.tools = update["tools"]
        return new_result

    initial_result.model_copy.side_effect = side_effect_model_copy

    mock_session.list_tools.return_value = initial_result

    # Mock firewall response (only returns allowed tools)
    mock_firewall.check_tool_list.return_value = [{"name": "allowed_tool"}]

    # Execute
    result = await proxy.list_tools()

    # Verify
    mock_firewall.check_tool_list.assert_called_once()
    assert len(result.tools) == 1
    assert result.tools[0].name == "allowed_tool"


@pytest.mark.asyncio
async def test_call_tool_allowed(proxy, mock_session, mock_firewall):
    # Setup
    tool_name = "safe_tool"
    args: dict[str, str] = {"param": "value"}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.SAFE, component=SecurityComponent.FIREWALL
    )

    mock_session.call_tool.return_value = "success"

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_called_once_with(tool_name, args)
    assert result == "success"


@pytest.mark.asyncio
async def test_call_tool_blocked(proxy, mock_session, mock_firewall, mock_mcp_modules):
    # Setup
    tool_name = "unsafe_tool"
    args: dict[str, str] = {}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.UNSAFE,
        component=SecurityComponent.FIREWALL,
        metadata={"reason": "bad tool"},
    )

    # Configure CallToolResult mock directly on the global types mock
    types_mock = mock_mcp_modules

    mock_result_instance = MagicMock()
    mock_result_instance.isError = True
    mock_result_instance.content = [MagicMock(text="🚫 Security Violation: bad tool")]

    # Configure the mock class constructor to return our instance
    types_mock.CallToolResult.return_value = mock_result_instance

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_not_called()
    assert result.isError is True
    assert "Security Violation: bad tool" in result.content[0].text


@pytest.mark.asyncio
async def test_call_tool_warning(proxy, mock_session, mock_firewall):
    # Setup
    tool_name = "risky_tool"
    args: dict[str, str] = {}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.WARNING,
        component=SecurityComponent.FIREWALL,
        metadata={"action": "warn"},
    )

    mock_session.call_tool.return_value = "success"

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_called_once_with(tool_name, args)
    assert result == "success"


def test_proxy_init_sets_server_from_server_info(mock_mcp_modules, mock_firewall):
    from deconvolute.clients.mcp import MCPProxy

    mock_session = MagicMock()

    # Mock server_info (snake_case)
    class MockInfo:
        name = "test_server_snake"
        version = "1.0.0"

    mock_session.server_info = MockInfo()
    if hasattr(mock_session, "serverInfo"):
        del mock_session.serverInfo

    # Init proxy
    MCPProxy(mock_session, mock_firewall)

    # Assert firewall.set_server was called with correct name
    mock_firewall.set_server.assert_called_once_with("test_server_snake", None)


def test_proxy_init_sets_server_from_serverInfo_camel_case(
    mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy

    mock_session = MagicMock()

    # Mock serverInfo (camelCase)
    class MockInfo:
        name = "test_server_camel"
        version = "1.0.0"

    mock_session.serverInfo = MockInfo()
    if hasattr(mock_session, "server_info"):
        del mock_session.server_info

    # Init proxy
    MCPProxy(mock_session, mock_firewall)

    # Assert firewall.set_server was called with correct name
    mock_firewall.set_server.assert_called_once_with("test_server_camel", None)


def test_proxy_init_no_server_info(mock_mcp_modules, mock_firewall):
    from deconvolute.clients.mcp import MCPProxy

    mock_session = MagicMock()

    # Clear both attributes
    if hasattr(mock_session, "server_info"):
        del mock_session.server_info
    if hasattr(mock_session, "serverInfo"):
        del mock_session.serverInfo

    # Init proxy
    MCPProxy(mock_session, mock_firewall)

    # Assert firewall.set_server was NOT called
    mock_firewall.set_server.assert_not_called()


def test_validate_server_identity_no_policy_version(
    mocker, mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy

    mock_session = mocker.MagicMock()
    mock_session.server_info = mocker.MagicMock(name="test_server", version="1.0.0")

    mock_policy = mocker.MagicMock()
    mock_policy.servers.get.return_value = mocker.MagicMock(version=None)
    mock_firewall.policy = mock_policy

    # Should not raise
    MCPProxy(mock_session, mock_firewall)


def test_validate_server_identity_missing_server_version(
    mocker, mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy
    from deconvolute.errors import ServerIdentityError

    mock_session = mocker.MagicMock()
    # Missing version entirely
    mock_session.server_info = mocker.MagicMock(name="test_server")
    del mock_session.server_info.version

    with pytest.raises(ServerIdentityError, match="Protocol violation"):
        MCPProxy(mock_session, mock_firewall)

    # Invalid type for version
    mock_session.server_info.version = 1.0  # Not a string
    with pytest.raises(ServerIdentityError, match="Protocol violation"):
        MCPProxy(mock_session, mock_firewall)


def test_validate_server_identity_version_match(
    mocker, mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy

    mock_session = mocker.MagicMock()
    mock_session.server_info = mocker.MagicMock(name="test_server", version="1.2.0")

    mock_policy = mocker.MagicMock()
    mock_policy.servers.get.return_value = mocker.MagicMock(version=">=1.0.0, <2.0.0")
    mock_firewall.policy = mock_policy

    # Should not raise
    MCPProxy(mock_session, mock_firewall)


def test_validate_server_identity_version_mismatch(
    mocker, mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy
    from deconvolute.errors import ServerIdentityError

    mock_session = mocker.MagicMock()
    mock_session.server_info = mocker.MagicMock(name="test_server", version="2.1.0")

    mock_policy = mocker.MagicMock()
    mock_policy.servers.get.return_value = mocker.MagicMock(version=">=1.0.0, <2.0.0")
    mock_firewall.policy = mock_policy

    with pytest.raises(ServerIdentityError, match="does not satisfy"):
        MCPProxy(mock_session, mock_firewall)


def test_validate_server_identity_invalid_policy_format(
    mocker, mock_mcp_modules, mock_firewall
):
    from deconvolute.clients.mcp import MCPProxy
    from deconvolute.errors import ServerIdentityError

    mock_session = mocker.MagicMock()
    mock_session.server_info = mocker.MagicMock(name="test_server", version="1.0.0")

    mock_policy = mocker.MagicMock()
    # Invalid semver constraint format
    mock_policy.servers.get.return_value = mocker.MagicMock(
        version="invalid-version-string"
    )
    mock_firewall.policy = mock_policy

    with pytest.raises(ServerIdentityError, match="Invalid version format evaluation"):
        MCPProxy(mock_session, mock_firewall)


@pytest.mark.asyncio
@patch("deconvolute.clients.mcp.get_backend")
async def test_list_tools_discovery_event_server_details(
    mock_get_backend, proxy, mock_session, mock_firewall
):
    mock_backend = MagicMock()
    mock_backend.log_discovery = AsyncMock()
    mock_get_backend.return_value = mock_backend

    # Mock server_info (snake_case) with details
    class MockInfo:
        name = "test_server_name"
        version = "1.0.0"
        title = "Test Server"
        description = "A server for testing"

    mock_session.server_info = MockInfo()

    # Setup mock tools
    tool_a = MagicMock(name="Tool_a")
    tool_a.name = "allowed_tool"
    tool_a.description = "Allowed Tool Description"
    tool_a.inputSchema = {"type": "object"}

    # Mock session response
    initial_result = MagicMock()
    initial_result.tools = [tool_a]

    def side_effect_model_copy(update):
        new_result = MagicMock()
        new_result.tools = update["tools"]
        return new_result

    initial_result.model_copy.side_effect = side_effect_model_copy
    mock_session.list_tools.return_value = initial_result

    # Mock firewall response
    mock_firewall.check_tool_list.return_value = [{"name": "allowed_tool"}]
    mock_snapshot = MagicMock()
    mock_snapshot.definition_hash = "mock_hash"
    mock_firewall.registry.get.return_value = mock_snapshot

    # Execute
    await proxy.list_tools()

    # Verify log_discovery was called
    mock_backend.log_discovery.assert_called_once()
    logged_event = mock_backend.log_discovery.call_args[0][0]

    assert logged_event.server_info["name"] == "test_server_name"
    assert logged_event.server_info["version"] == "1.0.0"
    assert logged_event.server_info["title"] == "Test Server"
    assert logged_event.server_info["description"] == "A server for testing"


@pytest.mark.asyncio
@patch("deconvolute.clients.mcp.get_backend")
async def test_list_tools_discovery_event_server_details_missing_fields(
    mock_get_backend, proxy, mock_session, mock_firewall
):
    mock_backend = MagicMock()
    mock_backend.log_discovery = AsyncMock()
    mock_get_backend.return_value = mock_backend

    # Mock server_info with minimal details
    class MockInfo:
        pass  # missing everything

    mock_session.server_info = MockInfo()

    # Setup mock tools
    initial_result = MagicMock()
    initial_result.tools = []
    initial_result.model_copy.return_value = initial_result
    mock_session.list_tools.return_value = initial_result
    mock_firewall.check_tool_list.return_value = []

    # Execute
    await proxy.list_tools()

    # Verify log_discovery was called
    mock_backend.log_discovery.assert_called_once()
    logged_event = mock_backend.log_discovery.call_args[0][0]

    assert logged_event.server_info["name"] == "unknown"
    assert logged_event.server_info["version"] == "unknown"
    assert "title" not in logged_event.server_info
    assert "description" not in logged_event.server_info


@pytest.mark.asyncio
@patch("deconvolute.core.api.mcp_guard")
@patch("mcp.ClientSession", new_callable=MagicMock)
@patch("mcp.client.stdio.stdio_client")
async def test_secure_stdio_session_impl(
    mock_stdio_client, mock_client_session, mock_mcp_guard
):
    from deconvolute.clients.mcp import secure_stdio_session_impl

    # Setup the async context manager mocks
    mock_stdio_client.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
    mock_session_instance = MagicMock()
    mock_client_session.return_value.__aenter__.return_value = mock_session_instance

    mock_guarded_session = MagicMock()
    mock_mcp_guard.return_value = mock_guarded_session

    # Mock server parameters
    params = SimpleNamespace(command="python", args=["server.py"])

    async with secure_stdio_session_impl(params, "policy.yaml") as session:
        assert session == mock_guarded_session

        # Verify mcp_guard was called with the correctly formatted StdioOrigin
        mock_mcp_guard.assert_called_once()
        call_kwargs = mock_mcp_guard.call_args[1]

        origin = call_kwargs.get("transport_origin")
        assert isinstance(origin, StdioOrigin)
        assert origin.command == "python"
        assert origin.args == ["server.py"]


@pytest.mark.asyncio
@patch("deconvolute.core.api.mcp_guard")
@patch("mcp.ClientSession", new_callable=MagicMock)
@patch("mcp.client.sse.sse_client")
async def test_secure_sse_session_impl(
    mock_sse_client, mock_client_session, mock_mcp_guard
):
    from deconvolute.clients.mcp import secure_sse_session_impl

    # Setup the async context manager mocks
    mock_sse_client.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
    mock_session_instance = MagicMock()
    mock_client_session.return_value.__aenter__.return_value = mock_session_instance

    mock_guarded_session = MagicMock()
    mock_mcp_guard.return_value = mock_guarded_session

    url = "https://api.trusted.com/sse"

    async with secure_sse_session_impl(url, "policy.yaml") as session:
        assert session == mock_guarded_session

        # Verify mcp_guard was called with the correctly formatted SSEOrigin
        mock_mcp_guard.assert_called_once()
        call_kwargs = mock_mcp_guard.call_args[1]

        origin = call_kwargs.get("transport_origin")
        assert isinstance(origin, SSEOrigin)
        assert origin.url == url
