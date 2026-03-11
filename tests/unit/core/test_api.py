import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deconvolute import DeconvoluteError
from deconvolute.core.api import (
    _resolve_configuration,
    a_scan,
    llm_guard,
    scan,
)
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)
from deconvolute.scanners.base import BaseScanner


@pytest.fixture
def mock_guard_defaults():
    """Patches get_guard_defaults to return a safe list."""
    with patch("deconvolute.core.api.get_guard_defaults") as mock:
        mock.return_value = []
        yield mock


@pytest.fixture
def mock_scan_defaults():
    """Patches get_scan_defaults to return a safe list."""
    with patch("deconvolute.core.api.get_scan_defaults") as mock:
        mock.return_value = []
        yield mock


@pytest.fixture
def mock_scanner():
    """A clean scanner that finds no threats."""
    d = MagicMock(spec=BaseScanner)
    d.check.return_value = SecurityResult(
        status=SecurityStatus.SAFE, component=SecurityComponent.SCANNER
    )
    d.a_check = AsyncMock(
        return_value=SecurityResult(
            status=SecurityStatus.SAFE, component=SecurityComponent.SCANNER
        )
    )
    return d


@pytest.fixture
def mock_threat_scanner():
    """A scanner that ALWAYS finds a threat."""
    d = MagicMock(spec=BaseScanner)
    d.check.return_value = SecurityResult(
        status=SecurityStatus.UNSAFE,
        component=SecurityComponent.SCANNER,
        metadata={"details": "Bad content"},
    )
    d.a_check = AsyncMock(
        return_value=SecurityResult(
            status=SecurityStatus.UNSAFE,
            component=SecurityComponent.SCANNER,
            metadata={"details": "Bad content"},
        )
    )
    return d


@pytest.fixture
def mock_openai_module():
    """
    Patches sys.modules with a fake openai module containing OpenAI and AsyncOpenAI
    classes.
    """
    fake_openai = MagicMock()

    class FakeOpenAI:
        pass

    FakeOpenAI.__module__ = "openai"
    FakeOpenAI.__name__ = "OpenAI"

    class FakeAsyncOpenAI:
        pass

    FakeAsyncOpenAI.__module__ = "openai"
    FakeAsyncOpenAI.__name__ = "AsyncOpenAI"

    fake_openai.OpenAI = FakeOpenAI
    fake_openai.AsyncOpenAI = FakeAsyncOpenAI

    with patch.dict(sys.modules, {"openai": fake_openai}):
        yield fake_openai


@pytest.fixture
def clean_client(mock_openai_module):
    """A Mock OpenAI-like client."""
    client = MagicMock(spec=mock_openai_module.OpenAI)
    # We also keep name/module for fallback logic if needed, but isinstance should win
    client.__class__.__name__ = "OpenAI"
    client.__class__.__module__ = "openai"
    client.__class__ = mock_openai_module.OpenAI
    return client


@pytest.fixture
def async_clean_client(mock_openai_module):
    """A Mock AsyncOpenAI-like client."""
    client = MagicMock(spec=mock_openai_module.AsyncOpenAI)
    client.__class__.__name__ = "AsyncOpenAI"
    client.__class__.__module__ = "openai"
    client.__class__ = mock_openai_module.AsyncOpenAI
    return client


def test_resolve_config_explicit():
    mock_scanner = MagicMock(spec=BaseScanner)
    scanners: list[BaseScanner] = [mock_scanner]
    result = _resolve_configuration(scanners, None)
    assert result == [mock_scanner]


def test_resolve_config_api_key_injection(mock_scanner):
    # Scanner has no api_key
    mock_scanner.api_key = None
    assert mock_scanner.api_key is None

    _resolve_configuration([mock_scanner], "secret-key")
    assert mock_scanner.api_key == "secret-key"


def test_resolve_config_api_key_no_overwrite(mock_scanner):
    mock_scanner.api_key = "existing-key"
    _resolve_configuration([mock_scanner], "new-key")
    assert mock_scanner.api_key == "existing-key"


def test_llm_guard_wrapper_sync(clean_client, mock_guard_defaults):
    mock_module = MagicMock()

    mock_proxy_class = MagicMock()
    mock_module.OpenAIProxy = mock_proxy_class

    # We mock deconvolute.clients.openai because llm_guard imports from it
    with patch.dict("sys.modules", {"deconvolute.clients.openai": mock_module}):
        result = llm_guard(clean_client)

        # Verify OpenAIProxy was instantiated with client
        mock_proxy_class.assert_called()
        assert result == mock_proxy_class.return_value


def test_llm_guard_wrapper_async(async_clean_client, mock_guard_defaults):
    mock_module = MagicMock()
    mock_proxy_class = MagicMock()
    mock_module.AsyncOpenAIProxy = mock_proxy_class

    with patch.dict("sys.modules", {"deconvolute.clients.openai": mock_module}):
        result = llm_guard(async_clean_client)

        mock_proxy_class.assert_called()
        assert result == mock_proxy_class.return_value


def test_llm_guard_unsupported_client(mock_guard_defaults):
    client = MagicMock()
    client.__class__.__name__ = "UnknownClient"
    client.__class__.__module__ = "unknown_lib"

    with pytest.raises(DeconvoluteError, match="Unsupported client type"):
        llm_guard(client)


def test_scan_uses_scan_defaults():
    with patch("deconvolute.core.api.get_scan_defaults") as mock_get_scan_defaults:
        mock_scanner = MagicMock()
        mock_scanner.check.return_value = MagicMock(status=SecurityStatus.SAFE)
        mock_scanner.check.return_value.safe = True  # Mock property
        mock_get_scan_defaults.return_value = [mock_scanner]

        scan("test content", scanners=None)

        mock_get_scan_defaults.assert_called_once()
        mock_scanner.check.assert_called_once()


def test_llm_guard_uses_guard_defaults():
    with patch("deconvolute.core.api.get_guard_defaults") as mock_get_guard_defaults:
        mock_client = MagicMock()
        # Mock client type to satisfy inspection checks
        mock_client.__class__.__module__ = "openai"
        mock_client.__class__.__name__ = "OpenAI"

        mock_get_guard_defaults.return_value = []

        try:
            llm_guard(mock_client, scanners=None)
        except Exception:  # noqa
            pass

        mock_get_guard_defaults.assert_called_once()


def test_scan_unsupported_client(mock_scan_defaults):
    client = MagicMock()
    client.__class__.__name__ = "UnknownClient"
    client.__class__.__module__ = "unknown_lib"

    with pytest.raises(DeconvoluteError, match="Unsupported client type"):
        llm_guard(client)


def test_llm_guard_openai_import_error(clean_client, mock_guard_defaults):
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
                llm_guard(clean_client)


def test_scan_threat_detected(mock_threat_scanner):
    result = scan("some content", scanners=[mock_threat_scanner])
    assert result.status == SecurityStatus.UNSAFE
    assert result.metadata.get("details") == "Bad content"


def test_scan_clean(mock_scanner):
    result = scan("safe content", scanners=[mock_scanner])
    assert result.status == SecurityStatus.SAFE
    assert result.component == SecurityComponent.SCANNER


def test_scan_calls_checks(mock_scanner):
    scan("test", scanners=[mock_scanner])
    mock_scanner.check.assert_called_once_with("test")


@pytest.mark.asyncio
async def test_a_scan_threat_detected(mock_threat_scanner):
    result = await a_scan("some content", scanners=[mock_threat_scanner])
    assert result.status == SecurityStatus.UNSAFE


@pytest.mark.asyncio
async def test_a_scan_clean(mock_scanner):
    result = await a_scan("safe content", scanners=[mock_scanner])
    assert result.status == SecurityStatus.SAFE


@pytest.mark.asyncio
async def test_a_scan_calls_checks(mock_scanner):
    await a_scan("test", scanners=[mock_scanner])
    mock_scanner.a_check.assert_called_once_with("test")


@pytest.mark.asyncio
async def test_secure_sse_session_passes_pin_dns():
    from deconvolute.core.api import secure_sse_session

    with patch("deconvolute.clients.mcp.secure_sse_session_impl") as mock_impl:
        # mock_impl returns an asynchronous context manager
        mock_impl.return_value.__aenter__ = AsyncMock(return_value="mock_session")
        mock_impl.return_value.__aexit__ = AsyncMock()

        async with secure_sse_session(
            "http://example.com/sse", pin_dns=False
        ) as session:
            assert session == "mock_session"

        mock_impl.assert_called_once_with(
            "http://example.com/sse",
            "deconvolute_policy.yaml",
            "snapshot",
            pin_dns=False,
        )
