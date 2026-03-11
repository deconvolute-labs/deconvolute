import asyncio
import socket
from pathlib import Path
from unittest.mock import patch

import pytest
import uvicorn
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Mount, Route

from deconvolute.core.api import secure_sse_session

# Setup a minimal valid MCP Server for the test target
mcp = Server("test-target-server")
sse = SseServerTransport("/messages")


async def handle_sse(request):
    # Core Assertion: Prove the firewall preserved the original Host header
    # even though the traffic was physically routed to 127.0.0.1
    assert request.headers.get("host") == "api.malicious-rebind.test:8010"

    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp.run(streams[0], streams[1], mcp.create_initialization_options())
    return Response()


# Mount the ASGI application
app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse, methods=["GET"]),
        Mount("/messages", app=sse.handle_post_message),
    ]
)


@pytest.mark.asyncio
@pytest.mark.parametrize("pin_dns", [True, False])
async def test_dns_pinning_transport_security(pin_dns):
    """
    Verifies that secure_sse_session correctly resolves and pins the IP address,
    ignoring the fake hostname while routing traffic accurately to the socket.
    """
    # Start the local server in the background
    config = uvicorn.Config(app, host="127.0.0.1", port=8010, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Give the socket a moment to bind
    await asyncio.sleep(1)

    # Use the static policy file stored alongside the test file
    policy_path = Path(__file__).parent / "transport_security_policy.yaml"

    # Patch the DNS resolver to simulate the fake domain pointing to localhost
    original_getaddrinfo = socket.getaddrinfo

    def mock_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host == "api.malicious-rebind.test":
            if port is None:
                # This is the Deconvolute Firewall doing its pre-flight check
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("127.0.0.1", 8010),
                    )
                ]
            else:
                # This is httpx trying to resolve the domain dynamically.
                # If pin_dns=False, it hits this block and crashes.
                raise socket.gaierror("Simulated DNS Failure: Unresolvable domain.")

        return original_getaddrinfo(host, port, family, type, proto, flags)

    try:
        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            if pin_dns:
                # Execute the secure session
                async with secure_sse_session(
                    url="http://api.malicious-rebind.test:8010/sse",
                    policy_path=str(policy_path),
                    pin_dns=pin_dns,
                ) as session:
                    await session.initialize()

                    # If we reach here, the firewall intercepted the request,
                    # pinned the IP to 127.0.0.1, preserved the host header,
                    # and established the SSE connection without httpx crashing.
                    assert session is not None
            else:
                # The TaskGroup around the connections raises an ExceptionGroup
                # when httpx inevitably fails to resolve the fake domain dynamically.
                with pytest.raises(ExceptionGroup):
                    async with secure_sse_session(
                        url="http://api.malicious-rebind.test:8010/sse",
                        policy_path=str(policy_path),
                        pin_dns=pin_dns,
                    ) as session:
                        await session.initialize()

    finally:
        # Guarantee the background server shuts down and frees the port
        server.should_exit = True
        await server_task
