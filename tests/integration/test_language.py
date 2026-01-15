import importlib.util

import pytest

from deconvolute.detectors.language.engine import LanguageDetector

# Check if lingua is actually installed in the environment
HAS_LINGUA = importlib.util.find_spec("lingua") is not None


@pytest.mark.skipif(not HAS_LINGUA, reason="Lingua not installed")
def test_real_lingua_integration():
    """
    Integration test that actually loads the heavy models
    and verifies the API contract with the real library.
    """
    # Initialize with a small subset to keep the test reasonably fast
    # We load English and French.
    detector = LanguageDetector(languages_to_load=["en", "fr"])

    # Test a clear English sentence
    res_en = detector.check("This is a totally normal English sentence.")
    assert res_en.detected_language == "en"
    assert res_en.threat_detected is False
    assert res_en.confidence > 0.8  # Real models should be confident here

    # Test a clear French sentence
    res_fr = detector.check("Bonjour tout le monde, comment ça va?")
    assert res_fr.detected_language == "fr"

    # Test a language we didn't load (e.g. German)
    # It should either fail detection or classify poorly, but not crash.
    res_de = detector.check("Das ist ein Test.")
    # In 'languages_to_load' mode, unknown languages often result in None
    # or a forced fit to one of the loaded ones with lower confidence.
    # We just ensure it returns a valid result object.
    assert res_de is not None
