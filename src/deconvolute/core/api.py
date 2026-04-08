import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal, TypeVar

if TYPE_CHECKING:
    import mcp.types

from deconvolute.constants import DECONVOLUTE_API_KEY, DEFAULT_MCP_POLICY_FILENAME
from deconvolute.core.defaults import get_guard_defaults, get_scan_defaults
from deconvolute.core.firewall import MCPFirewall
from deconvolute.core.policy import PolicyLoader
from deconvolute.errors import DeconvoluteError
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
    TransportOrigin,
)
from deconvolute.observability import configure_observability
from deconvolute.scanners.base import BaseScanner
from deconvolute.utils.logger import get_logger

logger = get_logger()

# TypeVar ensures that the IDE sees the return type as the same as the input type.
T = TypeVar("T")


def mcp_guard(
    client: T,
    policy_path: str = DEFAULT_MCP_POLICY_FILENAME,
    integrity: Literal["snapshot", "strict"] = "snapshot",
    transport_origin: TransportOrigin | None = None,
    init_result: "mcp.types.InitializeResult | None" = None,
    agent_id: str | None = None,
) -> T:
    """
    Wraps an MCP ClientSession with the Deconvolute Firewall.

    The returned proxy looks and behaves exactly like a ``ClientSession``. Your
    IDE autocompletion, type hints, and existing code all keep working. Under
    the hood the proxy intercepts every MCP call and enforces the security
    policy before forwarding it to the real session:

    - **Tool Discovery** (``list_tools``): Hides tools the policy disallows.
    - **Tool Execution** (``call_tool``): Raises ``SecurityResultError`` if the
      tool is unauthorized or the arguments violate a policy constraint.

    Args:
        client: The connected ``mcp.ClientSession`` instance.
        policy_path: Path to the security policy YAML file.
        integrity: The integrity check mode.
            - "snapshot" (Default): Verifies tools against the definition seen at
              startup. Fast, but vulnerable if the server changes tool definitions
              at runtime.
            - "strict": Forces a re-verification of the tool definition before every
              execution. Prevents "Rug Pull" attacks but adds a network round-trip.
        init_result: Optional mcp.types.InitializeResult. Pass this if the session
            was already initialized prior to wrapping, to ensure the firewall
            can evaluate the server's version and identity.
        agent_id: An optional identifier for the agent using this firewall.

    Returns:
        A CallToolResult with isError=True if the tool is unauthorized.

    Raises:
        ConfigurationError: If the policy file is missing or invalid.
        DeconvoluteError: If the ``mcp`` library is not installed.

    Examples:
        >>> from mcp import ClientSession
        >>> from deconvolute import mcp_guard
        >>>
        >>> async with ClientSession(...) as session:
        >>>     secure_session = mcp_guard(session, "policy.yaml", integrity="strict")
        >>>     # Use exactly as normal. Violations are stored in result.isError
        >>>     await secure_session.initialize()
        >>>
        >>>     # Call a tool as normal
        >>>     result = await secure_session.call_tool("read_file",{"path": "doc.txt"})
        >>>
        >>>     # Check for security blocks (standard MCP error handling)
        >>>     if result.isError:
        >>>         # This catches both Firewall blocks AND server-side errors
        >>>         print(f"Operation failed: {result.content[0].text}")
        >>>     else:
        >>>         print(f"Success: {result.content[0].text}")
    """
    # Configure Observability (Singleton)
    configure_observability()

    # Load & Validate Policy (Fails fast if missing)
    # We load this BEFORE importing the proxy to ensure configuration is valid.
    policy = PolicyLoader.load(policy_path)

    # Initialize the Firewall Engine
    firewall = MCPFirewall(policy, agent_id=agent_id)

    # Lazy Import the Proxy
    # We only import this here to avoid crashing apps that don't have 'mcp' installed.
    try:
        from deconvolute.clients.mcp import MCP_AVAILABLE, MCPProxy

        if not MCP_AVAILABLE:
            raise ImportError("The 'mcp' library is not installed.")

    except ImportError as e:
        raise DeconvoluteError(
            "Failed to import MCP support. Ensure the 'mcp' library is installed "
            "in your environment to use mcp_guard()."
        ) from e

    logger.debug(
        f"Deconvolute: Wrapping MCP Client with policy '{policy_path}' "
        f"(Integrity: {integrity})"
    )

    import typing

    # Return the wrapped client
    return typing.cast(
        T,
        MCPProxy(
            typing.cast(Any, client),
            firewall,
            integrity_mode=integrity,
            transport_origin=transport_origin,
            init_result=init_result,
        ),
    )


def llm_guard(
    client: T, scanners: list[BaseScanner] | None = None, api_key: str | None = None
) -> T:
    """
    Wraps an LLM client with Deconvolute security defenses.

    The returned proxy is a drop-in replacement for your LLM client. The same
    interface and same type hints apply. Every API call is transparently intercepted:
    prompts are scanned **before** they reach the provider, and responses are
    scanned **after** they arrive. If a threat is detected at either stage a
    ``SecurityResultError`` is raised so you can handle it in your application.

    Args:
        client: The original LLM client instance. Currently supports
            ``openai.OpenAI`` and ``openai.AsyncOpenAI``.
        scanners: An optional list of configured scanner instances.
            If ``None`` (default), the Standard Defense Suite is loaded
            (Canary + Language). If a list is provided, only those scanners
            are used (Strict Mode).
        api_key: The Deconvolute API key. If provided, it is injected into
            any scanner that requires it but is missing configuration.

    Returns:
        T: A proxy of the same type as *client* that enforces security.

    Raises:
        DeconvoluteError: If the client type is unsupported or if the required
            client library is not installed in the environment.
        SecurityResultError: At runtime, when a threat is detected in prompts
            or completions.

    Examples:
        >>> from openai import OpenAI
        >>> from deconvolute import llm_guard
        >>>
        >>> client = OpenAI(api_key="...")
        >>> secure_client = llm_guard(client)
        >>>
        >>> # Use as normal. Threats raise a SecurityResultError
        >>> completion = secure_client.chat.completions.create(...)
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_guard_defaults()

    # Inject API Keys
    scanners = _resolve_configuration(scanners, api_key)

    # Client Inspection
    # We attempt to import 'openai' to check isinstance.
    try:
        import openai

        if isinstance(client, (openai.OpenAI, openai.AsyncOpenAI)):
            try:
                from deconvolute.clients.openai import AsyncOpenAIProxy, OpenAIProxy
            except ImportError as e:
                # If we confirmed it's an OpenAI client but can't load the proxy,
                # it means the deconvolute installation is broken or environment issue.
                raise DeconvoluteError(
                    "Detected OpenAI client, but failed to import 'openai' library "
                    f"support. Ensure it is installed: {e}"
                ) from e

            if isinstance(client, openai.AsyncOpenAI):
                logger.debug("Deconvolute: Wrapping Async OpenAI client")
                return AsyncOpenAIProxy(client, scanners, api_key)  # type: ignore
            else:
                logger.debug("Deconvolute: Wrapping Sync OpenAI client")
                return OpenAIProxy(client, scanners, api_key)  # type: ignore

    except ImportError:
        pass

    # If we are here, either openai isn't installed OR client is not an instance.
    client_type = type(client).__name__
    module_name = type(client).__module__

    if "openai" in module_name:
        # It claims to be openai.
        # If we couldn't import openai, raising error is correct.
        pass

    # Fallback: If we don't recognize the client, we must fail secure.
    raise DeconvoluteError(
        f"Unsupported client type: '{client_type}' from module '{module_name}'. "
        "Deconvolute currently supports: OpenAI, AsyncOpenAI."
    )


def scan(
    content: str,
    scanners: list[BaseScanner] | None = None,
    api_key: str | None = None,
) -> SecurityResult:
    """
    Synchronously scans a string for threats using the configured scanners.

    Use this for **content-level** checks, e.g. RAG documents, tool outputs, or any
    text you want to validate outside a conversational lifecycle. Unlike
    ``llm_guard``, this function does not wrap a client; it takes a plain string
    and returns a ``SecurityResult``.

    Args:
        content: The text string to analyze.
        scanners: Optional list of scanners. If ``None``, uses the Standard
            Suite (Language scanner only. Canary is omitted because it
            requires a conversational lifecycle).
        api_key: Optional Deconvolute API key.

    Returns:
        SecurityResult: The result of the first scanner that found a threat,
        or a ``SAFE`` result if all scanners passed.

    Examples:
        >>> from deconvolute import scan
        >>>
        >>> result = scan(retrieved_document)
        >>> if not result.safe:
        ...     print(f"Blocked: {result.metadata}")
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_scan_defaults()

    # Resolve config
    scanners = _resolve_configuration(scanners, api_key)

    # Filter for scanners (scanners with check())
    # Note: All BaseScanner instances should have check()
    active_scanners = [d for d in scanners if hasattr(d, "check")]

    for scanner in active_scanners:
        result = scanner.check(content)
        if not result.safe:
            return result

    return SecurityResult(
        status=SecurityStatus.SAFE, component=SecurityComponent.SCANNER
    )


async def a_scan(
    content: str,
    scanners: list[BaseScanner] | None = None,
    api_key: str | None = None,
) -> SecurityResult:
    """
    Asynchronously scans a string for threats.

    Non-blocking counterpart of ``scan()``. Ideal for async pipelines
    (FastAPI, LangChain). See ``scan()`` for full parameter documentation.

    Examples:
        >>> from deconvolute import a_scan
        >>>
        >>> result = await a_scan(retrieved_document)
        >>> if not result.safe:
        ...     print(f"Blocked: {result.metadata}")
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_scan_defaults()

    scanners = _resolve_configuration(scanners, api_key)
    active_scanners = [d for d in scanners if hasattr(d, "check")]

    for scanner in active_scanners:
        result = await scanner.a_check(content)
        if not result.safe:
            return result

    return SecurityResult(
        status=SecurityStatus.SAFE, component=SecurityComponent.SCANNER
    )


def _resolve_configuration(
    scanners: list[BaseScanner], api_key: str | None
) -> list[BaseScanner]:
    """
    Internal helper to inject API keys into configured scanners.

    Args:
        scanners: The list of scanners (must not be None).
        api_key: The user-provided API key (or None).

    Returns:
        The configured scanners with keys injected.
    """
    final_key = api_key or os.getenv(DECONVOLUTE_API_KEY)

    # We only inject if the key is available and the scanner is unconfigured.
    if final_key:
        for s in scanners:
            if hasattr(s, "api_key") and getattr(s, "api_key", None) is None:
                s.api_key = final_key

    return scanners


@asynccontextmanager
async def secure_stdio_session(
    server_parameters: Any,
    policy_path: str = DEFAULT_MCP_POLICY_FILENAME,
    integrity: Literal["snapshot", "strict"] = "snapshot",
    agent_id: str | None = None,
) -> AsyncIterator[Any]:
    """
    Secure context manager for MCP stdio connections.

    Establishes a local stdio connection to an MCP server while enforcing
    strict origin validation to prevent Server Identity Spoofing. The local
    executable path and arguments are verified against the specified security
    policy before the session is yielded to the application.

    Args:
        server_parameters: The `mcp.StdioServerParameters` defining the local
            command and arguments used to spawn the server process.
        policy_path: Path to the security policy YAML file. Defaults to "policy.yaml".
        integrity: The integrity check mode.
            - "snapshot" (Default): Verifies tools against the definition seen at
                startup.
            - "strict": Forces a re-verification of the tool definition before every
                execution.
        agent_id: An optional identifier for the agent using this firewall.

    Yields:
        MCPProxy: A secure proxy wrapping the active `mcp.ClientSession`.

    Raises:
        TransportSpoofingError: If the actual `server_parameters` do not strictly match
            the expected transport origin defined in the server's policy.
        DeconvoluteError: If the 'mcp' library is not installed or initialization fails.
    """
    from deconvolute.clients.mcp import secure_stdio_session_impl

    async with secure_stdio_session_impl(
        server_parameters, policy_path, integrity, agent_id=agent_id
    ) as session:
        yield session


@asynccontextmanager
async def secure_sse_session(
    url: str,
    policy_path: str = DEFAULT_MCP_POLICY_FILENAME,
    integrity: Literal["snapshot", "strict"] = "snapshot",
    pin_dns: bool = True,
    agent_id: str | None = None,
) -> AsyncIterator[Any]:
    """
    Secure context manager for MCP Server-Sent Events (SSE) connections.

    Establishes a remote network connection to an MCP server while enforcing
    strict origin validation to prevent Server Identity Spoofing. The remote
    URL is verified against the specified security policy before the session
    is yielded to the application.

    Args:
        url: The HTTP(S) URL of the remote MCP server's SSE endpoint.
        policy_path: Path to the security policy YAML file. Defaults to "policy.yaml".
        integrity: The integrity check mode.
            - "snapshot" (Default): Verifies tools against the definition seen at
                startup.
            - "strict": Forces a re-verification of the tool definition before every
                execution.
        pin_dns: If True (default), resolves the hostname to an IP address exactly
            once during initialization and pins all subsequent transport requests
            to that IP. This automatically mitigates DNS Rebinding attacks.
        agent_id: An optional identifier for the agent using this firewall.

    Yields:
        MCPProxy: A secure proxy wrapping the active `mcp.ClientSession`.

    Raises:
        TransportSpoofingError: If the requested `url` does not strictly match
            the expected transport origin defined in the server's policy.
        DeconvoluteError: If the 'mcp' library is not installed or initialization fails.
    """
    from deconvolute.clients.mcp import secure_sse_session_impl

    async with secure_sse_session_impl(
        url, policy_path, integrity, pin_dns=pin_dns, agent_id=agent_id
    ) as session:
        yield session
