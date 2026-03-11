from typing import Any


class DeconvoluteError(Exception):
    """
    Base exception class for all errors raised by the Deconvolute SDK.
    Catching this allows users to handle any library-specific error.
    """

    pass


class ConfigurationError(DeconvoluteError):
    """
    Raised when the SDK is misconfigured or a method is called with invalid arguments.
    Example: Invalid prompt template, missing API keys, etc.
    """

    pass


class SecurityResultError(DeconvoluteError):
    """
    Raised when a security threat is detected or a policy violation occurs.

    This exception carries the `SecurityResult` payload, allowing the calling
    application to inspect exactly why the request was blocked (e.g. specific
    scanner, rule ID, or confidence score).

    Attributes:
        result (SecurityResult): The detailed security result.
    """

    def __init__(self, message: str, result: Any) -> None:
        super().__init__(message)
        self.result = result


class MCPSessionError(DeconvoluteError):
    """
    Raised when an integrity violation or state error occurs within the MCP Firewall.

    Examples:
    - Attempting to register a tool without a name.
    - Accessing a tool that was never registered (shadowing).
    """

    pass


class PolicyCompilationError(ConfigurationError):
    """Raised when a CEL policy condition contains syntax or logic errors."""

    pass


class PolicyValidationError(ConfigurationError):
    """Custom exception for clear policy formatting errors."""

    pass


class TransportSpoofingError(MCPSessionError):
    """
    Raised when the physical origin of a connection does not match
    the transport requirements defined in the security policy.
    """

    pass


class ServerIdentityError(MCPSessionError):
    """
    Raised when the server's identity (e.g. name, version, or cryptographic signature)
    does not match the expected security policy, indicating a potential spoofing
    or downgrade attack.
    """

    pass


class DNSResolutionError(DeconvoluteError):
    """
    Raised when strict DNS pinning is enabled but the target hostname cannot
    be resolved.
    """

    pass


class PinnedConnectionError(DeconvoluteError):
    """
    Raised when the secure transport fails to establish a TCP connection to any of
    the pinned IP addresses.
    """

    pass
