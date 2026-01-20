from unittest.mock import AsyncMock, Mock

import pytest

from deconvolute.clients.openai import (
    AsyncOpenAIProxy,
    OpenAIProxy,
    ThreatDetectedError,
)
from deconvolute.detectors.base import BaseDetector, DetectionResult


class MockInjector(BaseDetector):
    def inject(self, prompt):
        return prompt + " [INJECTED]", "token_123"

    def check(self, content, **kwargs):
        return DetectionResult(threat_detected=False, component="MockInjector")

    async def a_check(self, content, **kwargs):
        return DetectionResult(threat_detected=False, component="MockInjector")


class MockScanner(BaseDetector):
    def check(self, content, token=None, **kwargs):
        if "BAD_CONTENT" in content:
            return DetectionResult(
                threat_detected=True, component="MockScanner", token=token
            )
        return DetectionResult(threat_detected=False, component="MockScanner")

    async def a_check(self, content, token=None, **kwargs):
        # Reusing logic for parity
        return self.check(content, token=token)

    def clean(self, content, token=None):
        return content.replace("BAD_CONTENT", "CLEANED")


@pytest.fixture
def mock_openai_client():
    client = Mock()
    # Mocking client.chat.completions.create
    client.chat.completions.create = Mock()
    return client


@pytest.fixture
def mock_async_openai_client():
    client = Mock()
    client.chat.completions.create = AsyncMock()
    return client


def test_openai_proxy_initialization(mock_openai_client):
    """Test that OpenAIProxy initializes correctly."""
    injectors = [MockInjector()]
    scanners = [MockScanner()]
    proxy = OpenAIProxy(client=mock_openai_client, detectors=injectors + scanners)

    assert proxy._client == mock_openai_client
    assert proxy._injectors == injectors
    # Since MockInjector implements check/a_check (from BaseDetector), it is also
    # a scanner
    assert set(proxy._scanners) == set(injectors + scanners)
    # Verify attribute delegation
    assert proxy.chat.completions._module == mock_openai_client.chat.completions


def test_proxy_injection_flow(mock_openai_client):
    """Test that injectors modify the input messages."""
    injector = MockInjector()
    proxy = OpenAIProxy(client=mock_openai_client, detectors=[injector])

    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="Response"))]
    mock_openai_client.chat.completions.create.return_value = mock_response

    messages = [
        {"role": "system", "content": "System Prompt"},
        {"role": "user", "content": "User Prompt"},
    ]

    proxy.chat.completions.create(messages=messages, model="gpt-4")

    # Verify underlying client called with MODIFIED messages
    call_args = mock_openai_client.chat.completions.create.call_args
    assert call_args is not None
    called_messages = call_args[1]["messages"]

    # Note: The original messages list is modified in-place by the proxy
    assert called_messages[0]["content"] == "System Prompt [INJECTED]"


def test_proxy_scanning_flow_safe(mock_openai_client):
    """Test that scanners validate safe responses."""
    scanner = MockScanner()
    proxy = OpenAIProxy(client=mock_openai_client, detectors=[scanner])

    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="Safe Response"))]
    mock_openai_client.chat.completions.create.return_value = mock_response

    messages = [{"role": "system", "content": "Sys"}, {"role": "user", "content": "Hi"}]

    response = proxy.chat.completions.create(messages=messages)

    # Assert result is what we expect
    assert response.choices[0].message.content == "Safe Response"


def test_proxy_scanning_threat_detected(mock_openai_client):
    """Test that scanners raise ThreatDetectedError on bad content."""
    scanner = MockScanner()
    proxy = OpenAIProxy(client=mock_openai_client, detectors=[scanner])

    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="This has BAD_CONTENT"))]
    mock_openai_client.chat.completions.create.return_value = mock_response

    messages = [{"role": "system", "content": "Sys"}, {"role": "user", "content": "Hi"}]

    with pytest.raises(ThreatDetectedError) as excinfo:
        proxy.chat.completions.create(messages=messages)

    assert excinfo.value.result.component == "MockScanner"


def test_proxy_streaming_skips_scanners(mock_openai_client):
    """Test that streaming responses bypass scanners."""
    scanner = MockScanner()
    # Mock scanner.check to fail if called (to prove it wasn't called)
    scanner.check = Mock(side_effect=Exception("Should not be called"))

    proxy = OpenAIProxy(client=mock_openai_client, detectors=[scanner])

    mock_openai_client.chat.completions.create.return_value = ["stream", "chunks"]

    messages = [{"role": "system", "content": "Sys"}]

    # Call with stream=True
    proxy.chat.completions.create(messages=messages, stream=True)

    # Scanner should NOT have been called
    scanner.check.assert_not_called()


@pytest.mark.asyncio
async def test_async_proxy_flow(mock_async_openai_client):
    """Test AsyncOpenAIProxy flow."""
    injector = MockInjector()
    scanner = MockScanner()
    proxy = AsyncOpenAIProxy(
        client=mock_async_openai_client, detectors=[injector, scanner]
    )

    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="Safe Response"))]
    mock_async_openai_client.chat.completions.create.return_value = mock_response

    messages = [
        {"role": "system", "content": "System Prompt"},
        {"role": "user", "content": "User Prompt"},
    ]

    await proxy.chat.completions.create(messages=messages)

    # Verify injection
    call_args = mock_async_openai_client.chat.completions.create.call_args
    called_messages = call_args[1]["messages"]
    assert called_messages[0]["content"] == "System Prompt [INJECTED]"


@pytest.mark.asyncio
async def test_async_proxy_threat_detected(mock_async_openai_client):
    """Test AsyncOpenAIProxy raises ThreatDetectedError."""
    scanner = MockScanner()
    # Mock async check
    scanner.a_check = AsyncMock(
        return_value=DetectionResult(threat_detected=True, component="MockScanner")
    )

    proxy = AsyncOpenAIProxy(client=mock_async_openai_client, detectors=[scanner])

    mock_response = Mock()
    mock_response.choices = [Mock(message=Mock(content="BAD_CONTENT"))]
    mock_async_openai_client.chat.completions.create.return_value = mock_response

    messages = [{"role": "system", "content": "Sys"}]

    with pytest.raises(ThreatDetectedError):
        await proxy.chat.completions.create(messages=messages)
