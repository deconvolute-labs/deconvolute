from deconvolute.detectors.base import BaseDetector
from deconvolute.detectors.content.language.engine import LanguageDetector
from deconvolute.detectors.content.signature.engine import SignatureDetector
from deconvolute.detectors.integrity.canary.engine import CanaryDetector
from deconvolute.utils.logger import get_logger

logger = get_logger()


def get_guard_defaults() -> list[BaseDetector]:
    """
    Returns the standard suite of defenses for conversational guardrails.
    Includes Integrity (Canary) and Content (Language) checks.
    """
    return [
        CanaryDetector(token_length=16),
        LanguageDetector(allowed_languages=["en"]),
    ]


def get_scan_defaults() -> list[BaseDetector]:
    """
    Returns the standard suite of defenses for static content scanning.
    Optimized for deep inspection of prompts or documents.
    """
    detectors = [SignatureDetector()]

    return detectors
