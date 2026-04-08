import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from packaging.specifiers import SpecifierSet

from deconvolute.errors import ServerIdentityError
from deconvolute.models.observability import (
    TelemetryEventType,
    ToolData,
)

# We perform top-level imports here because this file is only ever
# imported if the user explicitly calls 'mcp_guard()', which implies
# they have the 'mcp' library installed.
try:
    import mcp.types as types
    from mcp import ClientSession

    MCP_AVAILABLE = True
except ImportError:
    # Fallback types for static analysis if mcp is missing
    # We use a dummy class so that types.ListToolsResult works in signatures
    class DummyTypes:
        ListToolsResult = Any
        CallToolResult = Any
        Tool = Any
        TextContent = Any
        PaginatedRequestParams = Any
        InitializeResult = Any

    types = DummyTypes  # type: ignore
    ClientSession = Any  # type: ignore
    MCP_AVAILABLE = False

from deconvolute.core.firewall import MCPFirewall
from deconvolute.core.types import ToolInterface
from deconvolute.models.observability import AccessEvent, DiscoveryEvent
from deconvolute.models.security import (
    IntegrityLevel,
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
    SSEOrigin,
    StdioOrigin,
    TransportOrigin,
)
from deconvolute.observability import get_backend
from deconvolute.utils.logger import get_logger

logger = get_logger()


class MCPProxy:
    """
    Transparent proxy for mcp.ClientSession that enforces security policies.

    This proxy sits between the Application and the MCP Client. It intercepts:
    1. list_tools(): To filter out tools that are blocked by policy.
    2. call_tool(): To block execution of unsafe tools or detect tampering.

    All other method calls (e.g. list_resources) are delegated directly to
    the underlying session.
    """

    def __init__(
        self,
        session: ClientSession,
        firewall: MCPFirewall,
        integrity_mode: IntegrityLevel = "snapshot",
        transport_origin: TransportOrigin | None = None,
        init_result: types.InitializeResult | None = None,
    ) -> None:
        """
        Args:
            session: The original connected mcp.ClientSession.
            firewall: The configured enforcement engine.
            integrity_mode: 'snapshot' (default) or 'strict'.
        """
        self._session = session
        self._firewall = firewall
        self._integrity_mode = integrity_mode
        self._transport_origin = transport_origin
        self._client_session_id = str(uuid.uuid4())

        # Hydrate the server identity either from the explicitly injected
        # initialization result, or attempt to pull it from the session.
        info = None
        if init_result:
            info = getattr(
                init_result, "server_info", getattr(init_result, "serverInfo", None)
            )
        else:
            info = getattr(session, "server_info", getattr(session, "serverInfo", None))

        self._validate_server_identity(info)

    def _validate_server_identity(self, info: Any) -> None:
        """
        Validates the server identity against the security policy.
        Raises ServerIdentityError if constraints are violated or protocol is invalid.
        """
        if not info or not hasattr(info, "name"):
            return

        server_name = info.name
        server_version = getattr(info, "version", None)

        # Strict Protocol Compliance Check
        # The MCP specification requires 'version' to be a string.
        if not server_version or not isinstance(server_version, str):
            logger.error(
                f"Protocol violation: Server '{server_name}' failed to report a "
                "valid version string."
            )
            raise ServerIdentityError(
                f"Protocol violation: Server '{server_name}' must report a "
                "version string."
            )

        # Register the server identity with the firewall
        self._firewall.set_server(
            server_name,
            server_version=server_version,
            transport_origin=self._transport_origin,
        )

        # Extract policy for this specific server
        server_policy = self._firewall.policy.servers.get(server_name)

        # Evaluate version constraints if they exist in the policy
        if server_policy and server_policy.version:
            try:
                specifiers = SpecifierSet(server_policy.version)
                if server_version not in specifiers:
                    logger.error(
                        f"Version mismatch for {server_name}. "
                        f"Expected {server_policy.version}, got {server_version}."
                    )
                    raise ServerIdentityError(
                        f"Server '{server_name}' version '{server_version}' does not "
                        "satisfy the security policy constraint: "
                        f"'{server_policy.version}'."
                    )
            except ValueError as e:
                # Fails closed if the policy contains an invalid SemVer string format
                raise ServerIdentityError(
                    f"Invalid version format evaluation for server '{server_name}': {e}"
                ) from e

    async def initialize(self, *args: Any, **kwargs: Any) -> Any:
        """
        Intercepts session initialization to dynamically extract the server's identity
        and enforce version constraints.
        """
        result = await self._session.initialize(*args, **kwargs)

        # The mcp SDK is in active development. We safely extract the identity
        # handling both the newer snake_case (server_info) and older camelCase
        info = getattr(result, "server_info", getattr(result, "serverInfo", None))
        self._validate_server_identity(info)
        return result

    async def __aenter__(self) -> "MCPProxy":
        """
        Allow using the guarded session directly in 'async with'.
        We enter the underlying session, but return 'self' (the Proxy).
        """
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Pass context exit to the underlying session."""
        await self._session.__aexit__(exc_type, exc_value, traceback)

    def __getattr__(self, name: str) -> Any:
        """Delegate any unknown methods (like list_resources) to the real session."""
        return getattr(self._session, name)

    def _normalize_tool(self, tool: types.Tool | Any) -> ToolInterface:
        """
        Explicitly maps the MCP library type to the internal ToolInterface.
        This isolates from Pydantic serialization changes (aliases, versions).
        """
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": getattr(
                tool, "inputSchema", getattr(tool, "input_schema", {})
            ),
        }

    async def list_tools(self, *args: Any, **kwargs: Any) -> types.ListToolsResult:
        """
        Intercepts tool discovery to hide blocked tools.

        1. Fetches all tools from the server.
        2. Passes them through the Firewall filter.
        3. Registers allowed tools in the SessionRegistry (snapshotting).
        4. Returns a ListToolsResult containing ONLY the allowed tools.
        """
        # Fetch real tools from the server
        result = await self._session.list_tools(*args, **kwargs)

        # Convert to dicts for firewall analysis
        tools_data = [self._normalize_tool(t) for t in result.tools]

        # Filter & Register
        # The firewall returns only the allowed tool dicts
        allowed_data = self._firewall.check_tool_list(tools_data)
        allowed_names = {t["name"] for t in allowed_data}

        # Observability Hook
        backend = get_backend()
        if backend:
            # Helper to build ToolData from internal interface
            def build_tool_data(tool_def: ToolInterface, is_allowed: bool) -> ToolData:
                tool_hash = None
                if is_allowed:
                    # If allowed, we can get the authoritative hash from the registry
                    snapshot = self._firewall.registry.get(tool_def["name"])
                    if snapshot:
                        tool_hash = snapshot.definition_hash

                return ToolData(
                    name=tool_def["name"],
                    description=tool_def.get("description"),
                    input_schema=tool_def.get("input_schema", {}),
                    definition_hash=tool_hash,
                )

            # Separate allowed vs blocked for the log
            allowed_event_data = []
            blocked_event_data = []

            for tool_def in tools_data:
                if tool_def["name"] in allowed_names:
                    allowed_event_data.append(
                        build_tool_data(tool_def, is_allowed=True)
                    )
                else:
                    blocked_event_data.append(
                        build_tool_data(tool_def, is_allowed=False)
                    )

            session_info = getattr(
                self._session, "server_info", getattr(self._session, "serverInfo", None)
            )
            server_details = {}
            if session_info:
                server_details["name"] = getattr(session_info, "name", "unknown")
                server_details["version"] = getattr(session_info, "version", "unknown")

                # Extract optional human-readable metadata if the server provides it
                title = getattr(session_info, "title", None)
                if title:
                    server_details["title"] = title

                description = getattr(session_info, "description", None)
                if description:
                    server_details["description"] = description

            event = DiscoveryEvent(
                client_session_id=self._client_session_id,
                tools_found_count=len(tools_data),
                tools_allowed_count=len(allowed_data),
                tools_allowed=allowed_event_data,
                tools_blocked=blocked_event_data,
                server_info=server_details,
            )
            backend.log_event(
                TelemetryEventType.SESSION_DISCOVERY, event.model_dump(mode="json")
            )

        # Reconstruct the result
        # We filter the original Pydantic objects to preserve data fidelity
        filtered_tools = [t for t in result.tools if t.name in allowed_names]

        # Return a copy of the result with the tools list replaced
        # usage of model_copy with update is correct for Pydantic v2
        return result.model_copy(update={"tools": filtered_tools})

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> types.CallToolResult:
        """
        Intercepts tool execution to enforce policy.

        1. Checks Firewall for Policy (Is this allowed?) and Integrity (Is this known?).
        2. If UNSAFE, returns a fake Error Result (prevents network call).
        3. If SAFE/WARNING, proceeds with the real network call.
        """
        # Ensure arguments is a dict (mcp allows None, but firewall expects dict)
        safe_args = arguments or {}

        current_tool_def: ToolInterface | None = None

        # Rug Pull detection
        if self._integrity_mode == "strict":
            try:
                # Lazy exhaustive paging
                tools_result = await self._session.list_tools()
                # Find our tool by name
                found_tool = next(
                    (t for t in tools_result.tools if t.name == name), None
                )

                cursor = getattr(
                    tools_result,
                    "next_cursor",
                    getattr(tools_result, "nextCursor", None),
                )
                seen_cursors = {cursor} if cursor else set()

                # If not found and more pages exist, keep paging
                while not found_tool and cursor:
                    page_params = types.PaginatedRequestParams(cursor=cursor)
                    tools_result = await self._session.list_tools(params=page_params)

                    found_tool = next(
                        (t for t in tools_result.tools if t.name == name), None
                    )
                    # Update cursor for the next iteration
                    next_cursor = getattr(
                        tools_result,
                        "next_cursor",
                        getattr(tools_result, "nextCursor", None),
                    )

                    if next_cursor in seen_cursors:
                        break  # Prevent infinite loop
                    if next_cursor:
                        seen_cursors.add(next_cursor)

                    cursor = next_cursor

                if found_tool:
                    current_tool_def = self._normalize_tool(found_tool)

                else:
                    # Tool vanished -> Synthetic Block
                    # We create a fake SecurityResult to ensure it gets logged
                    # properly below
                    sec_result = SecurityResult(
                        component=SecurityComponent.FIREWALL,
                        status=SecurityStatus.UNSAFE,
                        metadata={
                            "reason": "tool_vanished",
                            "integrity_check": "failed",
                        },
                    )
                    # We handle the return immediately if strict check fails,
                    # but we want to log it first.

                    # Log the event for the vanished tool
                    backend = get_backend()
                    if backend:
                        event = AccessEvent(
                            tool_name=name,
                            status=SecurityStatus.UNSAFE,
                            reason="integrity_violation",
                            metadata=sec_result.metadata,
                        )
                        backend.log_event(
                            TelemetryEventType.SESSION_ACCESS,
                            event.model_dump(mode="json"),
                        )

                    logger.warning(
                        f"MCPProxy (Strict): Tool '{name}' vanished from server "
                        "before execution."
                    )
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"🚫 Strict Integrity Violation: Tool '{name}' is "
                                "no longer advertised by the server.",
                            )
                        ],
                        isError=True,
                    )
            except Exception as e:
                try:
                    logger.error(f"MCPProxy (Strict): Failed to re-verify tool: {e}")
                    # Fail Closed
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=(
                                    "🚫 Strict Integrity Check Failed: "
                                    "Could not contact server."
                                ),
                            )
                        ],
                        isError=True,
                    )
                finally:
                    # Log the event for the system error
                    backend = get_backend()
                    if backend:
                        # Construct event for failure
                        event = AccessEvent(
                            tool_name=name,
                            status=SecurityStatus.UNSAFE,
                            reason="integrity_check_error",
                            metadata={
                                "error": str(e),
                                "component": "integrity_check",
                            },
                        )
                        backend.log_event(
                            TelemetryEventType.SESSION_ACCESS,
                            event.model_dump(mode="json"),
                        )

        # Security Check
        sec_result = self._firewall.check_tool_call(
            name, safe_args, current_tool_def=current_tool_def
        )

        if sec_result.status == SecurityStatus.UNSAFE and current_tool_def:
            # Rug Pull / Integrity Violation Logic
            # We include both the OFFENDING definition (from server) and the
            # TRUSTED definition (from registry) so the UI can render a Diff.
            sec_result.metadata["offending_definition"] = current_tool_def

            sec_result.metadata["offending_hash"] = (
                self._firewall.registry.compute_hash(current_tool_def)
            )

            trusted_snapshot = self._firewall.registry.get(name)
            if trusted_snapshot:
                # Reconstruct interface from snapshot for the log
                sec_result.metadata["trusted_definition"] = {
                    "name": trusted_snapshot.name,
                    "description": trusted_snapshot.description,
                    "input_schema": trusted_snapshot.input_schema,
                }
                sec_result.metadata["trusted_hash"] = trusted_snapshot.definition_hash

        # Observability Hook
        backend = get_backend()
        if backend:
            # We map the SecurityResult into an AccessEvent
            reason = sec_result.metadata.get("reason", "unknown")

            # If it's safe, we usually don't have a specific reason, so we label it
            if sec_result.status == SecurityStatus.SAFE:
                reason = "policy_allow"

            event = AccessEvent(
                client_session_id=self._client_session_id,
                tool_name=name,
                status=sec_result.status,
                reason=reason,
                metadata=sec_result.metadata,
            )
            backend.log_event(
                TelemetryEventType.SESSION_ACCESS, event.model_dump(mode="json")
            )

        if sec_result.status == SecurityStatus.UNSAFE:
            reason = sec_result.metadata.get("reason", "Blocked by policy")
            logger.warning(f"MCPProxy: Blocked tool '{name}': {reason}")

            # Block: Return a valid MCP Error Result
            # This allows the app to handle the failure gracefully without crashing.
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"🚫 Security Violation: {reason}",
                    )
                ],
                isError=True,
            )

        # Log Warnings if present (Audit mode)
        if sec_result.status == SecurityStatus.WARNING:
            logger.warning(
                f"MCPProxy: Warning for tool '{name}': {sec_result.metadata}"
            )

        # Allow: Execute the real tool call
        return await self._session.call_tool(name, arguments, *args, **kwargs)


@asynccontextmanager
async def secure_stdio_session_impl(
    server_parameters: Any,
    policy_path: str,
    integrity: IntegrityLevel = "snapshot",
    agent_id: str | None = None,
) -> AsyncIterator[Any]:
    """
    Implementation for the secure stdio transport wrapper.
    """
    from mcp.client.stdio import stdio_client

    from deconvolute.core.api import mcp_guard

    origin = StdioOrigin(
        type="stdio",
        command=server_parameters.command,
        args=server_parameters.args or [],
    )

    async with stdio_client(server_parameters) as (read, write):
        async with ClientSession(read, write) as session:
            guarded_session = mcp_guard(
                session,
                policy_path=policy_path,
                integrity=integrity,
                transport_origin=origin,
                agent_id=agent_id,
            )
            yield guarded_session


@asynccontextmanager
async def secure_sse_session_impl(
    url: str,
    policy_path: str,
    integrity: IntegrityLevel = "snapshot",
    pin_dns: bool = True,
    agent_id: str | None = None,
) -> AsyncIterator[Any]:
    """
    Implementation for the secure sse transport wrapper with transparent DNS pinning.

    This context manager connects to a remote MCP server using Server-Sent Events.
    If DNS pinning is enabled, it resolves the hostname asynchronously and routes
    the underlying TCP socket to the pinned IP, preventing DNS Rebinding attacks
    while fully preserving TLS certificate validation.

    Args:
        url (str): The target SSE endpoint URL.
        policy_path (str): Path to the Deconvolute security policy.
        integrity (IntegrityLevel, optional): The integrity check mode. Defaults to
            "snapshot".
        pin_dns (bool, optional): Whether to enforce DNS pinning. Defaults to True.

    Yields:
        AsyncIterator[Any]: The guarded MCP ClientSession proxy.
    """
    import asyncio
    import socket
    from urllib.parse import urlparse

    import httpx
    from mcp.client.sse import sse_client
    from mcp.shared._httpx_utils import McpHttpClientFactory, create_mcp_http_client

    from deconvolute.clients.transport import PinnedNetworkBackend
    from deconvolute.core.api import mcp_guard

    origin = SSEOrigin(type="sse", url=url)

    # Start with the standard MCP HTTPX factory
    factory: McpHttpClientFactory = create_mcp_http_client

    # DNS Pinning Defense Layer
    if pin_dns:
        parsed_url = urlparse(url)
        original_host = parsed_url.hostname

        if original_host:
            try:
                # DNS resolution
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(
                    original_host, port=None, type=socket.SOCK_STREAM
                )

                # Extract all unique IP strings, preserving the OS's priority order
                pinned_ips: list[str] = []
                for info in addr_info:
                    ip = info[4][0]
                    if ip not in pinned_ips:
                        pinned_ips.append(ip)

                logger.debug(
                    f"Deconvolute Firewall: Pinned DNS for {original_host} to "
                    f"{pinned_ips}"
                )

                def secure_httpx_factory(
                    *args: Any, **kwargs: Any
                ) -> httpx.AsyncClient:
                    # Obtain the fully configured client from the MCP SDK to
                    # preserve strict typing and default timeout configurations.
                    client = create_mcp_http_client(*args, **kwargs)

                    # Defensively wrap the internal connection pool.
                    # HTTPX encapsulates the network backend inside its transport layer.
                    if hasattr(client, "_transport") and hasattr(
                        client._transport, "_pool"
                    ):
                        pool = client._transport._pool
                        if hasattr(pool, "_network_backend"):
                            default_backend = pool._network_backend
                            pool._network_backend = PinnedNetworkBackend(
                                original_host=original_host,
                                pinned_ips=pinned_ips,
                                backend=default_backend,
                            )
                    return client

                # Override the default factory with our secure factory
                factory = secure_httpx_factory

            except (socket.gaierror, IndexError) as e:
                from deconvolute.errors import DNSResolutionError

                logger.error(
                    f"Deconvolute Firewall: Strict DNS pinning failed to resolve "
                    f"'{original_host}': {e}"
                )
                raise DNSResolutionError(
                    f"Strict DNS pinning is enabled, but '{original_host}' could not "
                    f"be resolved. Disable pin_dns if this environment does not "
                    f"support native DNS resolution. Details: {e}"
                ) from e

    async with sse_client(url, httpx_client_factory=factory) as (read, write):
        async with ClientSession(read, write) as session:
            guarded_session = mcp_guard(
                session,
                policy_path=policy_path,
                integrity=integrity,
                transport_origin=origin,
                agent_id=agent_id,
            )
            yield guarded_session
