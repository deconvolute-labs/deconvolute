import sys
from unittest.mock import MagicMock, patch

from deconvolute.core.defaults import get_standard_detectors
from deconvolute.detectors.integrity.canary.engine import CanaryDetector


# Helper to unimport a module if it's already loaded
def unimport(module_name):
    if module_name in sys.modules:
        del sys.modules[module_name]


def test_get_standard_detectors_with_lingua():
    """Verify LanguageDetector is included when import succeeds."""
    mock_module = MagicMock()
    mock_class = MagicMock()
    mock_class.__name__ = "LanguageDetector"
    # When instantiated, return a mock instance
    mock_instance = MagicMock()
    # We must give it a way to be identified.
    mock_instance.__class__.__name__ = "LanguageDetector"
    mock_class.return_value = mock_instance

    mock_module.LanguageDetector = mock_class

    with patch.dict(
        sys.modules, {"deconvolute.detectors.content.language.engine": mock_module}
    ):
        detectors = get_standard_detectors()

        # Check by class name to avoid isinstance issues with Magics
        has_language = any(
            d.__class__.__name__ == "LanguageDetector" for d in detectors
        )
        assert has_language, "LanguageDetector should be included when import succeeds"


def test_get_standard_detectors_includes_canary():
    """Verify standard detectors always include Canary."""
    # We patch the module to ensure LanguageDetector is NOT found/imported,
    # so we can verify Canary is present even in a minimal env.

    with patch.dict(sys.modules):
        # Simulate missing language module
        sys.modules["deconvolute.detectors.content.language.engine"] = None

        detectors = get_standard_detectors()

        # Verify Canary is present
        assert any(isinstance(d, CanaryDetector) for d in detectors)

        # Verify default config
        canary = next(d for d in detectors if isinstance(d, CanaryDetector))
        assert canary.token_length == 16
