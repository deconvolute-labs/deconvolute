from unittest.mock import MagicMock, patch

import pytest

from deconvolute.core.api import mcp_guard
from deconvolute.errors import DeconvoluteError


@patch("deconvolute.core.api.PolicyLoader")
@patch("deconvolute.core.api.MCPFirewall")
def test_mcp_guard_success(mock_firewall_cls, mock_policy_loader):
    # Setup
    mock_client = MagicMock()

    # Simulate mcp module and MCPProxy existing
    with patch.dict("sys.modules", {"mcp": MagicMock()}):
        with patch("deconvolute.clients.mcp.MCPProxy") as MockProxy:
            with patch("deconvolute.clients.mcp.MCP_AVAILABLE", True):
                # Execute
                result = mcp_guard(mock_client)

                # Verify
                mock_policy_loader.load.assert_called_once_with(
                    "deconvolute_policy.yaml"
                )
                mock_firewall_cls.assert_called_once()
                MockProxy.assert_called_once_with(
                    mock_client,
                    mock_firewall_cls.return_value,
                    integrity_mode="snapshot",
                    transport_origin=None,
                    init_result=None,
                )
                assert result == MockProxy.return_value


@patch("deconvolute.core.api.PolicyLoader")
def test_mcp_guard_raises_error_when_mcp_missing(mock_policy_loader):
    mock_client = MagicMock()

    # Simulate MCP_AVAILABLE = False
    # This mocks the module level variable in deconvolute.clients.mcp
    with patch("deconvolute.clients.mcp.MCP_AVAILABLE", False):
        with pytest.raises(DeconvoluteError, match="Failed to import MCP support"):
            mcp_guard(mock_client)


@patch("deconvolute.core.api.PolicyLoader")
def test_mcp_guard_raises_import_error_directly(mock_policy_loader):
    # Simulate an import error by removing the module from sys.modules
    # This ensures that even if the import itself fails (e.g. syntax error or missing
    # file), we catch it and raise DeconvoluteError.
    mock_client = MagicMock()

    # We set the module to None to trigger ModuleNotFoundError on import attempt
    with patch.dict("sys.modules", {"deconvolute.clients.mcp": None}):
        with pytest.raises(DeconvoluteError, match="Failed to import MCP support"):
            mcp_guard(mock_client)
