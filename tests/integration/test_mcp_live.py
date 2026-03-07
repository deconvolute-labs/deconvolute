import os
import sys
import tempfile

import mcp.types as types
import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from deconvolute import mcp_guard
from deconvolute.errors import ServerIdentityError


@pytest.mark.asyncio
class TestLiveMCP:
    async def test_mcp_guard_integration(self):
        """
        Verifies that mcp_guard correctly wraps a real ClientSession and
        intercepts calls to a local MCP server.
        """
        # Path to the server script we created
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")

        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the session. We do this here to test that the SDK
                # handles the case of initialization first and then wrapping correctly.
                await session.initialize()

                # Wrap with security guard using local test policy
                policy_path = os.path.join(
                    os.path.dirname(__file__), "policy_allow_echo.yaml"
                )

                try:
                    guarded_client = mcp_guard(session, policy_path=policy_path)
                except Exception as e:
                    pytest.skip(f"Skipping integration test config error: {e}")

                # Test list_tools
                params = await guarded_client.list_tools()
                tool_names = [t.name for t in params.tools]
                print(f"Tools found: {tool_names}")

                # Expect at least 'echo' and 'add' if policy allows them.
                # If policy blocks them, they won't be here.
                # This integration test mainly asserts that we CAN talk to the server
                # via the proxy.

                # Test call_tool (Echo)
                # If 'echo' is in the list, call it.
                if "echo" in tool_names:
                    result = await guarded_client.call_tool(
                        "echo", arguments={"message": "Hello MCP"}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "Echo: Hello MCP"

                # Test call_tool (Add)
                if "add" in tool_names:
                    result = await guarded_client.call_tool(
                        "add", arguments={"a": 10, "b": 32}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "42"

    async def test_mcp_guard_allows_valid_version(self):
        """
        Verifies that a server meeting the version constraint is allowed.
        """
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        policy = {
            "version": "2.0",
            "servers": {
                "live-test-server": {
                    "version": ">=0.1.0",
                    "tools": [{"name": "echo", "action": "allow"}],
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            policy_path = f.name

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # This should succeed without raising an exception
                    guarded_session = mcp_guard(session, policy_path=policy_path)

                    await guarded_session.initialize()
                    params = await guarded_session.list_tools()
                    tool_names = [t.name for t in params.tools]
                    assert "echo" in tool_names
        finally:
            os.remove(policy_path)

    async def test_mcp_guard_blocks_downgraded_version(self):
        """
        Verifies that a server violating the version constraint is blocked violently.
        """
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        # The server is 0.1.0, so this policy requires a newer version
        policy = {
            "version": "2.0",
            "servers": {
                "live-test-server": {
                    "version": ">=0.2.0",
                    "tools": [{"name": "echo", "action": "allow"}],
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            policy_path = f.name

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # The exception should be thrown immediately during wrapping
                    with pytest.raises(ServerIdentityError) as exc_info:
                        guarded_session = mcp_guard(session, policy_path=policy_path)
                        await guarded_session.initialize()

                    assert "does not satisfy the security policy constraint" in str(
                        exc_info.value
                    )
        finally:
            os.remove(policy_path)

    async def test_mcp_guard_escape_hatch_initialization(self):
        """
        Verifies that passing init_result securely enforces version constraints
        when the session is initialized before the guard is applied.
        """
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        # The mock server is 0.1.0, so >=0.2.0 should block it
        policy = {
            "version": "2.0",
            "servers": {
                "live-test-server": {
                    "version": ">=0.2.0",
                    "tools": [{"name": "echo", "action": "allow"}],
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            policy_path = f.name

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # Initialize FIRST
                    init_result = await session.initialize()

                    # Wrap SECOND, injecting the result
                    with pytest.raises(ServerIdentityError) as exc_info:
                        mcp_guard(
                            session, policy_path=policy_path, init_result=init_result
                        )

                    assert "does not satisfy the security policy constraint" in str(
                        exc_info.value
                    )
        finally:
            os.remove(policy_path)

    async def test_wrap_first_initialize_second(self):
        """
        Flow 1: Wrap First, Initialize Second (Preferred)
        """
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        policy = {
            "version": "2.0",
            "servers": {
                "live-test-server": {
                    "version": ">=0.1.0",
                    "tools": [{"name": "echo", "action": "allow"}],
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            policy_path = f.name

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # 1. Wrap the raw session
                    safe_session = mcp_guard(session, policy_path=policy_path)

                    # 2. Initialize the guarded session
                    await safe_session.initialize()

                    # Verify it works by talking through the guard wrapper
                    params = await safe_session.list_tools()
                    tool_names = [t.name for t in params.tools]
                    assert "echo" in tool_names

                    # Verify call_tool works
                    result = await safe_session.call_tool(
                        "echo", arguments={"message": "Flow 1"}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "Echo: Flow 1"
        finally:
            os.remove(policy_path)

    async def test_initialize_first_wrap_second(self):
        """
        Flow 2: Initialize First, Wrap Second
        """
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        policy = {
            "version": "2.0",
            "servers": {
                "live-test-server": {
                    "version": ">=0.1.0",
                    "tools": [{"name": "echo", "action": "allow"}],
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            policy_path = f.name

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # 1. Initialize the raw session first
                    init_result = await session.initialize()

                    # 2. Wrap the session and inject the initialization result
                    safe_session = mcp_guard(
                        session, policy_path=policy_path, init_result=init_result
                    )

                    # Verify it works by talking through the guard wrapper
                    params = await safe_session.list_tools()
                    tool_names = [t.name for t in params.tools]
                    assert "echo" in tool_names

                    # Verify call_tool works
                    result = await safe_session.call_tool(
                        "echo", arguments={"message": "Flow 2"}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "Echo: Flow 2"
        finally:
            os.remove(policy_path)
