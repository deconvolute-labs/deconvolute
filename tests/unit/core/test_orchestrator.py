import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deconvolute.core.orchestrator import (
    DeconvoluteError,
    _resolve_configuration,
    a_scan,
    guard,
    scan,
)
from deconvolute.detectors.base import BaseDetector, DetectionResult


@pytest.fixture
def mock_defaults():
    """Patches get_standard_detectors to return a safe list."""
    with patch("deconvolute.core.orchestrator.get_standard_detectors") as mock:
        mock.return_value = []
        yield mock


@pytest.fixture
def mock_detector():
    """A clean detector that finds no threats."""
    d = MagicMock(spec=BaseDetector)
    d.check.return_value = DetectionResult(
        threat_detected=False, component="MockDetector"
    )
    d.a_check = AsyncMock(
        return_value=DetectionResult(threat_detected=False, component="MockDetector")
    )
    return d


@pytest.fixture
def mock_threat_detector():
    """A detector that ALWAYS finds a threat."""
    d = MagicMock(spec=BaseDetector)
    d.check.return_value = DetectionResult(
        threat_detected=True,
        component="ThreatDetector",
        metadata={"details": "Bad content"},
    )
    d.a_check = AsyncMock(
        return_value=DetectionResult(
            threat_detected=True,
            component="ThreatDetector",
            metadata={"details": "Bad content"},
        )
    )
    return d


@pytest.fixture
def clean_client():
    """A Mock OpenAI-like client."""
    # We fake the class structure to pass `type(client).__module__` checks
    client = MagicMock()
    client.__class__.__name__ = "OpenAI"
    client.__class__.__module__ = "openai"
    return client


@pytest.fixture
def async_clean_client():
    """A Mock AsyncOpenAI-like client."""
    client = MagicMock()
    client.__class__.__name__ = "AsyncOpenAI"
    client.__class__.__module__ = "openai"
    return client


def test_resolve_config_defaults():
    with patch(
        "deconvolute.core.orchestrator.get_standard_detectors"
    ) as mock_get_defaults:
        mock_get_defaults.return_value = ["default_detector"]
        result = _resolve_configuration(None, None)
        assert result == ["default_detector"]
        mock_get_defaults.assert_called_once()


def test_resolve_config_explicit():
    detectors = ["custom"]
    result = _resolve_configuration(detectors, None)
    assert result == ["custom"]


def test_resolve_config_api_key_injection(mock_detector):
    # Detector has no api_key
    mock_detector.api_key = None
    assert mock_detector.api_key is None

    _resolve_configuration([mock_detector], "secret-key")
    assert mock_detector.api_key == "secret-key"


def test_resolve_config_api_key_no_overwrite(mock_detector):
    mock_detector.api_key = "existing-key"
    _resolve_configuration([mock_detector], "new-key")
    assert mock_detector.api_key == "existing-key"


def test_guard_wrapper_sync(clean_client, mock_defaults):
    mock_module = MagicMock()

    mock_proxy_class = MagicMock()
    mock_module.OpenAIProxy = mock_proxy_class

    with patch.dict("sys.modules", {"deconvolute.clients.openai": mock_module}):
        result = guard(clean_client)

        # Verify OpenAIProxy was instantiated with client
        mock_proxy_class.assert_called()
        assert result == mock_proxy_class.return_value


def test_guard_wrapper_async(async_clean_client, mock_defaults):
    mock_module = MagicMock()
    mock_proxy_class = MagicMock()
    mock_module.AsyncOpenAIProxy = mock_proxy_class

    with patch.dict("sys.modules", {"deconvolute.clients.openai": mock_module}):
        result = guard(async_clean_client)

        mock_proxy_class.assert_called()
        assert result == mock_proxy_class.return_value


def test_guard_unsupported_client(mock_defaults):
    client = MagicMock()
    client.__class__.__name__ = "UnknownClient"
    client.__class__.__module__ = "unknown_lib"

    with pytest.raises(DeconvoluteError, match="Unsupported client type"):
        guard(client)


def test_guard_openai_import_error(clean_client):
    # Simulate openai being detected by name but failing to import the proxy module
    # This one is hard because guard has a local import for the OpenAIProxy etc.
    original_import = __import__

    def mock_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "deconvolute.clients.openai":
            raise ImportError("Simulated broken installation")
        return original_import(name, globals, locals, fromlist, level)

    # We also need to make sure it's not already in sys.modules
    with patch.dict(sys.modules):
        if "deconvolute.clients.openai" in sys.modules:
            del sys.modules["deconvolute.clients.openai"]

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(DeconvoluteError, match="client, but failed to import"):
                guard(clean_client)


def test_scan_threat_detected(mock_threat_detector):
    result = scan("some content", detectors=[mock_threat_detector])
    assert result.threat_detected is True
    assert result.metadata.get("details") == "Bad content"


def test_scan_clean(mock_detector):
    result = scan("safe content", detectors=[mock_detector])
    assert result.threat_detected is False
    assert result.component == "Scanner"


def test_scan_calls_checks(mock_detector):
    scan("test", detectors=[mock_detector])
    mock_detector.check.assert_called_once_with("test")


@pytest.mark.asyncio
async def test_a_scan_threat_detected(mock_threat_detector):
    result = await a_scan("some content", detectors=[mock_threat_detector])
    assert result.threat_detected is True


@pytest.mark.asyncio
async def test_a_scan_clean(mock_detector):
    result = await a_scan("safe content", detectors=[mock_detector])
    assert result.threat_detected is False


@pytest.mark.asyncio
async def test_a_scan_calls_checks(mock_detector):
    await a_scan("test", detectors=[mock_detector])
    mock_detector.a_check.assert_called_once_with("test")
