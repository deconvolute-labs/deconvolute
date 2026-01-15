import sys

import pytest

from deconvolute.detectors.language.engine import LanguageDetector
from deconvolute.errors import ConfigurationError


@pytest.fixture
def mock_lingua(mocker):
    """
    Mocks the entire lingua library to avoid loading 100MB models during tests.
    """
    # 1. Patch the Builder class
    mock_builder = mocker.patch(
        "deconvolute.detectors.language.engine.LanguageDetectorBuilder"
    )

    # 2. Create the mock detector instance that the builder returns
    mock_detector_instance = mocker.MagicMock()
    mock_builder.from_all_languages.return_value.build.return_value = (
        mock_detector_instance
    )
    mock_builder.from_iso_codes_639_1.return_value.build.return_value = (
        mock_detector_instance
    )

    # 3. Setup the side effect for detection logic
    def side_effect_detect(text):
        if "french" in text.lower() or "bonjour" in text.lower():
            # Simulate French detection
            mock_res = mocker.MagicMock()
            mock_res = mocker.MagicMock()
            mock_res.iso_code_639_1.name = "FR"
            return mock_res
        elif "english" in text.lower() or "hello" in text.lower():
            # Simulate English detection
            mock_res = mocker.MagicMock()
            mock_res.iso_code_639_1.name = "EN"
            return mock_res
        return None  # Simulate unknown

    mock_detector_instance.detect_language_of.side_effect = side_effect_detect

    # Return the builder mock so tests can check calls if needed
    return mock_builder


@pytest.fixture
def mock_lingua_missing(mocker):
    """
    Simulates a missing lingua library.
    """
    # 1. Patch sys.modules to hide 'lingua'
    mocker.patch.dict(sys.modules, {"lingua": None})

    # 2. Patch the global HAS_LINGUA flag in the engine module
    # We must patch this because the import happens before the test runs
    mocker.patch("deconvolute.detectors.language.engine.HAS_LINGUA", False)


def test_init_raises_error_if_lingua_missing(mock_lingua_missing):
    """It should raise ConfigurationError if lingua is not installed."""
    with pytest.raises(ConfigurationError) as exc:
        LanguageDetector()
    assert "pip install deconvolute[language]" in str(exc.value)


def test_init_loads_all_languages_by_default(mock_lingua):
    """It should load all languages if no specific list is provided."""
    detector = LanguageDetector()

    # Verify builder was called with from_all_languages
    mock_lingua.from_all_languages.assert_called_once()
    assert detector._detector is not None


def test_init_optimizes_loaded_languages(mocker, mock_lingua):
    """It should only load specific languages if languages_to_load is set."""
    # We need to mock IsoCode639_1 enum lookup since logic uses it
    # We use spec to ensure we mimic existence
    mock_enum = mocker.patch(
        "deconvolute.detectors.language.engine.IsoCode639_1", spec=["EN", "FR"]
    )
    mock_enum.EN = "ENUM_EN"
    mock_enum.FR = "ENUM_FR"

    _ = LanguageDetector(languages_to_load=["en", "fr"])

    # Verify it used the optimized builder method
    mock_lingua.from_iso_codes_639_1.assert_called_once()

    # Verify arguments passed to builder were our mocked enums
    args, _ = mock_lingua.from_iso_codes_639_1.call_args
    assert "ENUM_EN" in args
    assert "ENUM_FR" in args


def test_init_raises_error_if_no_valid_languages(mocker, mock_lingua):
    """It should raise ConfigurationError if languages_to_load has no valid codes."""
    # Use spec=[] so any attribute access raises AttributeError

    with pytest.raises(ConfigurationError) as exc:
        LanguageDetector(languages_to_load=["invalid1", "invalid2"])

    assert "No valid languages found" in str(exc.value)


def test_init_logs_warning_for_unsupported_language(mocker, mock_lingua):
    """It should log a warning for unsupported languages but load valid ones."""
    # Use spec with only "EN" so "XX" raises AttributeError
    mock_enum = mocker.patch(
        "deconvolute.detectors.language.engine.IsoCode639_1", spec=["EN"]
    )
    # We need to set the value for EN since spec only defines existence, not value
    mock_enum.EN = "ENUM_EN"

    mock_logger = mocker.patch("deconvolute.detectors.language.engine.logger")

    _ = LanguageDetector(languages_to_load=["en", "xx"])

    # Verify warning
    mock_logger.warning.assert_called_with(
        "Language code 'xx' not supported by Lingua. Skipping."
    )
    # Verify builder building "en"
    args, _ = mock_lingua.from_iso_codes_639_1.call_args
    assert "ENUM_EN" in args


def test_check_detects_language_correctly(mock_lingua):
    """It should correctly identify the language."""
    detector = LanguageDetector()
    result = detector.check("Hello world (english)")

    assert result.threat_detected is False
    assert result.detected_language == "en"
    assert result.confidence == 1.0


def test_check_empty_input(mock_lingua):
    """It should handle empty input gracefully."""
    detector = LanguageDetector()

    res_empty = detector.check("")
    assert res_empty.detected_language is None
    assert res_empty.confidence == 0.0
    assert res_empty.threat_detected is False

    res_none = detector.check(None)  # type: ignore[arg-type]
    assert res_none.detected_language is None
    assert res_none.threat_detected is False


def test_check_unknown_language(mock_lingua):
    """It should handle unknown language detection."""
    detector = LanguageDetector()
    # mock_lingua will return None for text not matching "english" or "french"
    result = detector.check("zzzzzzzz")

    assert result.detected_language is None
    assert result.confidence == 0.0
    assert result.threat_detected is False


def test_check_policy_violation(mock_lingua):
    """It should flag a threat if the language is not in the allowed list."""
    # Policy: Only allow English
    detector = LanguageDetector(allowed_languages=["en", "english"])

    # Input: French
    result = detector.check("Bonjour le monde (french)")

    assert result.threat_detected is True
    assert result.detected_language == "fr"
    assert result.metadata["reason"] == "policy_violation"


def test_check_policy_success(mock_lingua):
    """It should pass if the language is allowed."""
    detector = LanguageDetector(allowed_languages=["fr", "french"])
    result = detector.check("Bonjour le monde (french)")

    assert result.threat_detected is False


def test_check_correspondence_mismatch(mock_lingua):
    """It should flag a threat if Output language != Input language."""
    detector = LanguageDetector()  # No static policy

    # User asks in English, Model replies in French
    result = detector.check(
        content="Bonjour (french)", reference_text="Hello (english)"
    )

    assert result.threat_detected is True
    assert result.detected_language == "fr"
    assert result.metadata["reason"] == "correspondence_mismatch"
    assert result.metadata["reference_language"] == "en"


def test_check_correspondence_case_mismatch(mock_lingua):
    """It should handle case differences in language code matching."""

    # Even if internal logic or input has weird casing, it should normalize
    # Assuming the mocks return normalized names.
    # We test that our comparison logic is case-safe if we were to force it.

    # We can effectively test this by checking allowed_languages being case insensitive
    detector_policy = LanguageDetector(allowed_languages=["EN", "Fr"])

    # Input: French -> match
    res_fr = detector_policy.check("Bonjour (french)")
    assert res_fr.threat_detected is False

    # Input: English -> match
    res_en = detector_policy.check("Hello (english)")
    assert res_en.threat_detected is False


def test_check_correspondence_success(mock_lingua):
    """It should pass if Output language == Input language."""
    detector = LanguageDetector()

    result = detector.check(
        content="Hello there (english)", reference_text="Hi friend (english)"
    )

    assert result.threat_detected is False
    assert result.detected_language == "en"


@pytest.mark.asyncio
async def test_a_check_works_async(mock_lingua):
    """It should work asynchronously."""
    detector = LanguageDetector()
    result = await detector.a_check("Hello world (english)")

    assert result.detected_language == "en"
    assert result.threat_detected is False
