from .core.api import (
    a_scan,
    llm_guard,
    mcp_guard,
    scan,
    secure_sse_session,
    secure_stdio_session,
)
from .errors import DeconvoluteError, SecurityResultError
from .models.security import SecurityResult
from .scanners.content import (
    LanguageScanner,
    LanguageSecurityResult,
    SignatureScanner,
)
from .scanners.integrity import CanaryScanner, CanarySecurityResult

__version__ = "0.1.3"

# The explicitly tested and supported version of the upstream MCP SDK
__mcp_supported_version__ = "1.26.0"

__all__ = [
    "llm_guard",
    "mcp_guard",
    "scan",
    "a_scan",
    "CanaryScanner",
    "CanarySecurityResult",
    "SecurityResult",
    "LanguageScanner",
    "LanguageSecurityResult",
    "SignatureScanner",
    "SecurityResultError",
    "secure_stdio_session",
    "secure_sse_session",
    "DeconvoluteError",
]
