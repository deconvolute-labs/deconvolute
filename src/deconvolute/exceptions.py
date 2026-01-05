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


class SecurityDetectedError(DeconvoluteError):
    """
    Raised when a security threat is detected.

    Note: The SDK methods (like scanner.scan() or canary.check()) generally
    return a Result object rather than raising this. This exception is provided
    for users who prefer to raise it in their own logic based on the Result.
    """

    pass
