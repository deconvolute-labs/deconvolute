class DeconvoluteError(Exception):
    """Base exception for Deconvolute."""

    pass


class ScannerError(DeconvoluteError):
    """Raised when a scanner fails."""

    pass


class SanitizerError(DeconvoluteError):
    """Raised when sanitization fails."""

    pass
