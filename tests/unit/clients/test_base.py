from unittest.mock import Mock

import pytest

from deconvolute.clients.base import BaseProxy
from deconvolute.detectors.base import BaseDetector


class ConcreteProxy(BaseProxy):
    """Concrete implementation of BaseProxy for testing."""

    pass


class MockInjector(BaseDetector):
    def inject(self, prompt):
        return prompt, "token"

    def check(self, content, token=None):
        return None

    async def a_check(self, content, token=None):
        return None


class MockScanner(BaseDetector):
    def check(self, content, token=None):
        return True

    async def a_check(self, content, token=None):
        return True


class MockDualDetector(BaseDetector):
    def inject(self, prompt):
        return prompt, "token"

    def check(self, content, token=None):
        return True

    async def a_check(self, content, token=None):
        return True


def test_base_proxy_cannot_be_instantiated_directly():
    """Test that BaseProxy raises TypeError on direct instantiation."""
    with pytest.raises(TypeError, match="BaseProxy cannot be instantiated directly"):
        BaseProxy(client=Mock(), detectors=[])


def test_concrete_proxy_initialization():
    """Test that a subclass can be instantiated."""
    client = Mock()
    proxy = ConcreteProxy(client=client, detectors=[])
    assert proxy._client == client
    assert proxy._detectors == []


def test_detector_sorting():
    """Test that detectors are correctly sorted into injectors and scanners."""

    injector = MockInjector()
    scanner = MockScanner()
    dual = MockDualDetector()

    detectors = [injector, scanner, dual]
    proxy = ConcreteProxy(client=Mock(), detectors=detectors)

    # Check injectors
    assert injector in proxy._injectors
    assert dual in proxy._injectors
    assert scanner not in proxy._injectors

    # Check scanners
    assert scanner in proxy._scanners
    assert dual in proxy._scanners
    assert injector in proxy._scanners


def test_attribute_delegation():
    """Test that attributes are delegated to the underlying client."""
    client = Mock()
    client.some_method = Mock(return_value="result")
    client.some_property = "value"

    proxy = ConcreteProxy(client=client, detectors=[])

    # Test method call
    assert proxy.some_method() == "result"
    client.some_method.assert_called_once()

    # Test property access
    assert proxy.some_property == "value"


def test_attribute_delegation_missing_attribute():
    """Test that AttributeError is raised for missing attributes."""
    client = Mock(spec=[])  # Empty mock
    proxy = ConcreteProxy(client=client, detectors=[])

    with pytest.raises(AttributeError):
        _ = proxy.non_existent_attribute
