from .core.orchestrator import a_scan, guard, scan
from .detectors.base import DetectionResult
from .detectors.content import LanguageDetector, LanguageResult, SignatureDetector
from .detectors.integrity import CanaryDetector, CanaryResult
from .errors import DeconvoluteError, ThreatDetectedError

__version__ = "0.1.0a8"

__all__ = [
    "guard",
    "scan",
    "a_scan",
    "CanaryDetector",
    "CanaryResult",
    "DetectionResult",
    "LanguageDetector",
    "LanguageResult",
    "SignatureDetector",
    "ThreatDetectedError",
    "DeconvoluteError",
]
