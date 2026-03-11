from unittest.mock import AsyncMock, MagicMock

import httpcore
import pytest

from deconvolute.clients.transport import PinnedNetworkBackend
from deconvolute.errors import PinnedConnectionError


@pytest.fixture
def mock_backend():
    backend = MagicMock(spec=httpcore.AsyncNetworkBackend)
    backend.connect_tcp = AsyncMock()
    return backend


@pytest.mark.asyncio
async def test_pinned_network_backend_bypasses_non_target(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com", pinned_ips=["1.2.3.4"], backend=mock_backend
    )

    # Try connecting to a non-matching host
    mock_stream = AsyncMock()
    mock_backend.connect_tcp.return_value = mock_stream

    stream = await backend.connect_tcp("api.other.com", 80)

    assert stream == mock_stream
    mock_backend.connect_tcp.assert_called_once_with(
        host="api.other.com",
        port=80,
        timeout=None,
        local_address=None,
        socket_options=None,
    )


@pytest.mark.asyncio
async def test_pinned_network_backend_connects_to_pinned_ip(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com",
        pinned_ips=["1.2.3.4", "5.6.7.8"],
        backend=mock_backend,
    )

    mock_stream = AsyncMock()
    mock_backend.connect_tcp.return_value = mock_stream

    stream = await backend.connect_tcp("api.target.com", 443)

    assert stream == mock_stream
    mock_backend.connect_tcp.assert_called_once_with(
        host="1.2.3.4", port=443, timeout=None, local_address=None, socket_options=None
    )
    # The IP should be locked
    assert backend._locked_ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_pinned_network_backend_fast_path(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com", pinned_ips=["1.2.3.4"], backend=mock_backend
    )
    # Pre-lock an IP
    backend._locked_ip = "1.2.3.4"

    mock_stream = AsyncMock()
    mock_backend.connect_tcp.return_value = mock_stream

    stream = await backend.connect_tcp("api.target.com", 443)

    assert stream == mock_stream
    mock_backend.connect_tcp.assert_called_once_with(
        host="1.2.3.4", port=443, timeout=None, local_address=None, socket_options=None
    )


@pytest.mark.asyncio
async def test_pinned_network_backend_fallback_on_failure(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com",
        pinned_ips=["invalid_ip", "1.2.3.4"],
        backend=mock_backend,
    )

    mock_stream = AsyncMock()

    # Fail first, succeed second
    mock_backend.connect_tcp.side_effect = [
        Exception("Connection Refused"),
        mock_stream,
    ]

    stream = await backend.connect_tcp("api.target.com", 443)

    assert stream == mock_stream
    assert mock_backend.connect_tcp.call_count == 2

    # Check that second call used the fallback IP
    assert mock_backend.connect_tcp.call_args_list[1][1]["host"] == "1.2.3.4"
    assert backend._locked_ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_pinned_network_backend_raises_error_if_all_fail(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com",
        pinned_ips=["10.0.0.1", "10.0.0.2"],
        backend=mock_backend,
    )

    # All fail
    mock_backend.connect_tcp.side_effect = Exception("Network Down")

    with pytest.raises(
        PinnedConnectionError, match="Failed to connect to any pinned IPs"
    ):
        await backend.connect_tcp("api.target.com", 443)

    assert mock_backend.connect_tcp.call_count == 2


@pytest.mark.asyncio
async def test_pinned_network_backend_raises_error_if_no_ips(mock_backend):
    backend = PinnedNetworkBackend(
        original_host="api.target.com", pinned_ips=[], backend=mock_backend
    )

    with pytest.raises(PinnedConnectionError, match="No valid IP addresses provided"):
        await backend.connect_tcp("api.target.com", 443)
