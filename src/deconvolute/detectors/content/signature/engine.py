import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yara

from deconvolute.constants import DEFAULT_SIGNATURE_RULE_FILENAME
from deconvolute.detectors.base import BaseDetector, DetectionResult
from deconvolute.errors import ConfigurationError
from deconvolute.utils.logger import get_logger

logger = get_logger()


DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / DEFAULT_SIGNATURE_RULE_FILENAME


class SignatureDetector(BaseDetector):
    """
    Detects known threats, adversarial patterns, and PII using signatures.

    This detector performs high-performance pattern matching against text content.
    It is designed to be the primary defense layer for scanning document ingestion
    pipelines (RAG) or validating raw user inputs.

    By default, it uses the SDK's bundled security baseline (`default.yar`), which
    covers common jailbreaks and injection attempts. Users can override this by
    providing a path to their own custom YARA rules file.

    Attributes:
        local_rules_path (Path): The file path to the compiled or source YARA rules.
        _rules (yara.Rules): The compiled YARA rules object (C-extension).
        _executor (ThreadPoolExecutor): Thread pool for offloading blocking match
            operations.
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
    ):
        """
        Initialize the SignatureDetector with a specific rule set.

        The detector compiles the rules immediately upon initialization. This is a
        blocking operation designed to fail fast if the rule file is missing or
        malformed.

        Args:
            rules_path: Optional path to a local signature rule file (.yar).
                If None, the detector loads the internal `default.yar` bundled
                with the SDK.

        Raises:
            ConfigurationError: If the rule file does not exist or contains syntax
                errors that prevent compilation.
        """
        self.local_rules_path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH

        self._rules = None
        self._executor = ThreadPoolExecutor()

        self._load_rules()

    def _load_rules(self):
        """
        Compiles the local signature rules from disk.

        Raises:
            ConfigurationError: Wraps yara.Error if compilation fails.
        """
        if not self.local_rules_path.exists():
            raise ConfigurationError(
                f"Signature rules file not found at: {self.local_rules_path}"
            )

        try:
            self._rules = yara.compile(filepath=str(self.local_rules_path))
            logger.debug(f"Loaded local signature rules from {self.local_rules_path}")
        except yara.Error as e:
            raise ConfigurationError(
                f"Failed to compile local signature rules: {e}"
            ) from e

    def check(self, content: str, **kwargs: Any) -> DetectionResult:
        """
        Synchronously scans the provided content against the loaded singature rules.

        This method performs a blocking scan. While underlying YARA is highly optimized,
        scanning very large documents may block the execution thread briefly.

        Args:
            content: The string content to scan.
            **kwargs: Additional arguments (unused, kept for interface compatibility).

        Returns:
            DetectionResult: A structured result containing:
                - threat_detected (bool): True if any rule matched.
                - metadata (dict): specific matches, tags, and match count.
        """
        if not self._rules:
            # Should not happen given init raises on failure, but safety check
            return DetectionResult(threat_detected=False, component="SignatureDetector")

        # Match returns a list of Match objects
        matches = self._rules.match(data=content)

        if not matches:
            return DetectionResult(threat_detected=False, component="SignatureDetector")

        # Extract metadata from matches
        match_names = [m.rule for m in matches]
        tags = []
        for m in matches:
            tags.extend(m.tags)
            # Some rules define tags in metadata explicitly
            if "tag" in m.meta:
                tags.append(m.meta["tag"])

        # Deduplicate tags
        tags = list(set(tags))

        return DetectionResult(
            threat_detected=True,
            component="SignatureDetector",
            metadata={"matches": match_names, "tags": tags, "count": len(matches)},
        )

    async def a_check(self, content: str, **kwargs: Any) -> DetectionResult:
        """
        Async version.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, lambda: self.check(content, **kwargs)
        )
