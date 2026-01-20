from typing import Any

from deconvolute.detectors.base import BaseDetector


class BaseProxy:
    """
    Abstract Base Class for all Client Proxies.

    This class provides the core infrastructure for storing state (client, keys,
    detectors) and transparently delegating attributes. It organizes detectors based
    on their capabilities (Injecting vs. Scanning).

    Attributes:
        _client (Any): The original, wrapped LLM client instance.
        api_key (str | None): The Deconvolute API Key.
        _detectors (list[BaseDetector]): The full list of active security detectors.
        _injectors (list[BaseDetector]): Detectors that implement 'inject'.
            Used to modify the input prompt (e.g. Canary).
        _scanners (list[BaseDetector]): Detectors that implement 'check'.
            Used to scan the output response (e.g. Language, Canary).
    """

    def __init__(
        self,
        client: Any,
        detectors: list[BaseDetector],
        api_key: str | None = None,
    ):
        """
        Initializes the proxy infrastructure.

        Args:
            client: The original LLM client instance.
            detectors: A strict list of detectors. The factory (guard) is responsible
                for resolving defaults before calling this.
            api_key: Optional Deconvolute API key.
        """
        # Enforce Abstract Nature
        if type(self) is BaseProxy:
            raise TypeError(
                "BaseProxy cannot be instantiated directly. Use a subclass."
            )

        self._client = client
        self.api_key = api_key
        self._detectors = detectors

        # Capability-Based Sorting

        # Injectors
        # Detectors that modify the state/prompt BEFORE execution.
        # Corresponds to the 'inject()' method.
        self._injectors = [d for d in self._detectors if hasattr(d, "inject")]

        # Scanners
        # Detectors that analyze text. In the context of this proxy, they are used
        # to validate the LLM response. In other contexts (like scan()), they might
        # check documents.
        # Corresponds to the 'check()' method.
        self._scanners = [d for d in self._detectors if hasattr(d, "check")]

    def __getattr__(self, name: str) -> Any:
        """
        Delegates attribute access to the underlying client.

        This enables 'transparency': if the user calls a method we don't
        explicitly intercept, it passes through to the real client.
        """
        return getattr(self._client, name)
