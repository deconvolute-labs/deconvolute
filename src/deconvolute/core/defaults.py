from deconvolute.detectors.base import BaseDetector
from deconvolute.detectors.content.language.engine import LanguageDetector
from deconvolute.detectors.integrity.canary.engine import CanaryDetector
from deconvolute.utils.logger import get_logger

logger = get_logger()


def get_standard_detectors() -> list[BaseDetector]:
    """
    Returns the standard suite of defenses (Canary + Language).
    """
    return [
        CanaryDetector(token_length=16),
        LanguageDetector(allowed_languages=["en"]),
    ]
