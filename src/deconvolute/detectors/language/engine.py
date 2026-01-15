import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from deconvolute.detectors.base import BaseDetector
from deconvolute.errors import ConfigurationError
from deconvolute.utils.logger import get_logger

from .models import LanguageResult

try:
    from lingua import IsoCode639_1, Language, LanguageDetectorBuilder

    HAS_LINGUA = True
except ImportError:
    HAS_LINGUA = False

logger = get_logger()


class LanguageDetector(BaseDetector):
    """
    Detects language inconsistencies to prevent Payload Splitting attacks.

    This detector can verify if the output language matches:
    1. A specific allow-list (Policy Mode).
    2. The language of the input prompt (Correspondence Mode).

    Requires 'lingua-language-detector' installed.
    https://github.com/pemistahl/lingua-py
    """

    def __init__(
        self,
        allowed_languages: list[str] | None = None,
        languages_to_load: list[str] | None = None,
    ):
        """
        Args:
            allowed_languages: List of ISO 639-1 codes (e.g. ['en', 'fr']).
                               If None, no static policy is enforced (useful if
                               you only want to check input-output correspondence).

            languages_to_load: Performance optimization. List of ISO codes to load
                               into memory.
                             - If None (Default): Loads ALL languages (~100MB).
                                Maximum accuracy.
                             - If provided: Only loads these models. Much lighter,
                                but cannot detect languages outside this list.
        """
        if not HAS_LINGUA:
            raise ConfigurationError(
                "LanguageDetector requires the 'lingua' library.\n"
                "Please install it with: pip install deconvolute[language]"
            )

        self.allowed_codes = [code.lower() for code in (allowed_languages or [])]
        self._executor = ThreadPoolExecutor()

        if languages_to_load:
            # Load only specific languages
            # We map strings "en" -> IsoCode639_1.EN
            selected_languages = []
            for code in languages_to_load:
                try:
                    # Lingua expects uppercase ISO codes for the enum lookup
                    # We use getattr which raises AttributeError if invalid
                    iso_enum = getattr(IsoCode639_1, code.upper())
                    selected_languages.append(iso_enum)
                except AttributeError:
                    logger.warning(
                        f"Language code '{code}' not supported by Lingua. Skipping."
                    )

            if not selected_languages:
                raise ConfigurationError(
                    "No valid languages found in 'languages_to_load'."
                )

            self._detector = LanguageDetectorBuilder.from_iso_codes_639_1(
                *selected_languages
            ).build()
            logger.debug(
                f"LanguageDetector loaded in lightweight mode: {languages_to_load}"
            )

        else:
            # Default mode, load all languages (~100MB)
            # Necessary for robust anomaly detection
            self._detector = LanguageDetectorBuilder.from_all_languages().build()

    def _detect(self, text: str) -> tuple[str | None, float]:
        """
        Helper to get (iso_code, confidence).
        Returns: (iso_code like 'en', confidence 0.0-1.0)
        """
        if not text or not text.strip():
            return None, 0.0

        # Lingua returns the specific Language enum
        result: Language | None = self._detector.detect_language_of(text)
        if not result:
            return None, 0.0

        # Convert Enum "Language.ENGLISH" -> "en"
        # Lingua's iso_code_639_1 is the standard 2-letter code
        iso_code: str = result.iso_code_639_1.name.lower()

        # Lingua is deterministic in single-language mode, so we treat it as high
        # confidence unless it returns None.
        return iso_code, 1.0

    def check(self, content: str, **kwargs: Any) -> LanguageResult:
        """
        Checks if content matches allowed languages or reference text.

        Args:
            content: The text to analyze (usually LLM output).
            **kwargs:
                reference_text (str): If provided, 'content' must match the language
                                      of this text (usually User Input).
        """
        detected_code, confidence = self._detect(content)

        reference_text = kwargs.get("reference_text")
        if reference_text:
            ref_code, _ = self._detect(reference_text)

            # If we successfully detected both languages and they differ
            if detected_code and ref_code and detected_code != ref_code:
                return LanguageResult(
                    threat_detected=True,
                    detected_language=detected_code,
                    confidence=confidence,
                    allowed_languages=[ref_code] + self.allowed_codes,
                    component="LanguageDetector",
                    metadata={
                        "reason": "correspondence_mismatch",
                        "reference_language": ref_code,
                    },
                )

        # Check Allowlist (Policy)
        if self.allowed_codes and detected_code:
            if detected_code not in self.allowed_codes:
                return LanguageResult(
                    threat_detected=True,
                    detected_language=detected_code,
                    confidence=confidence,
                    allowed_languages=self.allowed_codes,
                    component="LanguageDetector",
                    metadata={"reason": "policy_violation"},
                )

        return LanguageResult(
            threat_detected=False,
            detected_language=detected_code,
            confidence=confidence,
            allowed_languages=self.allowed_codes,
            component="LanguageDetector",
        )

    async def a_check(self, content: str, **kwargs: Any) -> LanguageResult:
        """Async version of check() using a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, lambda: self.check(content, **kwargs)
        )
