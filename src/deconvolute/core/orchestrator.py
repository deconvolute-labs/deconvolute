import os
from typing import TypeVar

from deconvolute.core.defaults import get_guard_defaults, get_scan_defaults
from deconvolute.detectors.base import BaseDetector, DetectionResult
from deconvolute.errors import DeconvoluteError
from deconvolute.utils.logger import get_logger

logger = get_logger()

# TypeVar ensures that the IDE sees the return type as the same as the input type.
T = TypeVar("T")


def guard(
    client: T, detectors: list[BaseDetector] | None = None, api_key: str | None = None
) -> T:
    """
    Wraps an LLM client with Deconvolute security defenses.

    This function acts as a factory that inspects the provided client (e.g. OpenAI,
    AsyncOpenAI), determines its type, and returns a transparent Proxy object that
    intercepts API calls to enforce security policies.

    Args:
        client: The original LLM client instance. Currently supports objects from
            the 'openai' library (Sync and Async).
        detectors: An optional list of configured detector instances.
            If None (default), the Standard Defense Suite is loaded (Canary + Language).
            If a list is provided, only those detectors are used (Strict Mode).
        api_key: The Deconvolute API key. If provided, it is injected into any
            detector that requires it but is missing configuration.

    Returns:
        A Proxy object that mimics the interface of the original client but
        executes security checks on inputs (inject) and outputs (scan).

    Raises:
        DeconvoluteError: If the client type is unsupported or if the required
            client library is not installed in the environment.
    """
    # Load Defaults if needed
    if detectors is None:
        detectors = get_guard_defaults()

    # Inject API Keys
    detectors = _resolve_configuration(detectors, api_key)

    # Client Inspection
    # We use string inspection to avoid importing libraries that might not be installed.
    client_type = type(client).__name__
    module_name = type(client).__module__

    # Routing & Lazy Loading
    # We only import the specific proxy implementation if we detect the client.

    # OpenAI Support
    if "openai" in module_name:
        try:
            from deconvolute.clients.openai import AsyncOpenAIProxy, OpenAIProxy

            # Detect Async vs Sync based on class name convention
            if "Async" in client_type:
                logger.debug(
                    f"Deconvolute: Wrapping Async OpenAI client ({client_type})"
                )
                return AsyncOpenAIProxy(client, detectors, api_key)  # type: ignore
            else:
                logger.debug(
                    f"Deconvolute: Wrapping Sync OpenAI client ({client_type})"
                )
                return OpenAIProxy(client, detectors, api_key)  # type: ignore

        except ImportError as e:
            # This handles the case where the object claims to be from 'openai'
            # but the library cannot be imported (e.g. broken environment).
            raise DeconvoluteError(
                f"Detected OpenAI client, but failed to import 'openai' library. "
                f"Ensure it is installed: {e}"
            ) from e

    # Fallback: If we don't recognize the client, we must fail secure.
    raise DeconvoluteError(
        f"Unsupported client type: '{client_type}' from module '{module_name}'. "
        "Deconvolute currently supports: OpenAI, AsyncOpenAI."
    )


def scan(
    content: str,
    detectors: list[BaseDetector] | None = None,
    api_key: str | None = None,
) -> DetectionResult:
    """
    Synchronously scans a string for threats using the configured detectors.

    This function is designed for 'Content' scanning in RAG pipelines (e.g. checking
    retrieved documents) or tool outputs. It skips 'Integrity' checks (like Canary)
    that require a conversational lifecycle.

    Args:
        content: The text string to analyze.
        detectors: Optional list of detectors. If None, uses Standard Suite.
        api_key: Optional Deconvolute API key.

    Returns:
        DetectionResult: The result of the first detector that found a threat,
        or a clean result if all passed.
    """
    # Load Defaults if needed
    if detectors is None:
        detectors = get_scan_defaults()

    # Resolve config
    detectors = _resolve_configuration(detectors, api_key)

    # Filter for scanners (detectors with check())
    scanners = [d for d in detectors if hasattr(d, "check")]

    for detector in scanners:
        result = detector.check(content)
        if result.threat_detected:
            return result

    return DetectionResult(threat_detected=False, component="Scanner")


async def a_scan(
    content: str,
    detectors: list[BaseDetector] | None = None,
    api_key: str | None = None,
) -> DetectionResult:
    """
    Asynchronously scans a string for threats.

    See `scan()` for full documentation. This method is non-blocking and ideal
    for high-throughput async pipelines (FastAPI, LangChain).
    """
    # Load Defaults if needed
    if detectors is None:
        detectors = get_scan_defaults()

    detectors = _resolve_configuration(detectors, api_key)
    scanners = [d for d in detectors if hasattr(d, "check")]

    for detector in scanners:
        result = await detector.a_check(content)
        if result.threat_detected:
            return result

    return DetectionResult(threat_detected=False, component="Scanner")


def _resolve_configuration(
    detectors: list[BaseDetector], api_key: str | None
) -> list[BaseDetector]:
    """
    Internal helper to inject API keys into configured detectors.

    Args:
        detectors: The list of detectors (must not be None).
        api_key: The user-provided API key (or None).

    Returns:
        The configured detectors with keys injected.
    """
    final_key = api_key or os.getenv("DECONVOLUTE_API_KEY")

    # We only inject if the key is available and the detector is unconfigured.
    if final_key:
        for d in detectors:
            if hasattr(d, "api_key") and getattr(d, "api_key", None) is None:
                d.api_key = final_key

    return detectors
