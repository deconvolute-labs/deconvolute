from .core.orchestrator import a_scan, guard, scan
from .detectors.base import DetectionResult
from .detectors.content import LanguageDetector
from .detectors.integrity import CanaryDetector
from .errors import DeconvoluteError, ThreatDetectedError

__version__ = "0.1.0a7"

__all__ = [
    "guard",
    "scan",
    "a_scan",
    "CanaryDetector",
    "DetectionResult",
    "LanguageDetector",
    "ThreatDetectedError",
    "DeconvoluteError",
]
