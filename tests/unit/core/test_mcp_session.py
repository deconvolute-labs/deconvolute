import hashlib
import json
from unittest.mock import patch

import pytest

from deconvolute.constants import DECONVOLUTE_API_KEY
from deconvolute.core.mcp_session import MCPSessionRegistry
from deconvolute.core.types import ToolInterface
from deconvolute.errors import MCPSessionError
from deconvolute.models.observability import SecurityEventType


class TestMCPSessionRegistry:
    @pytest.fixture
    def registry(self):
        return MCPSessionRegistry("test_server", "1.0.0")

    def test_initialization(self, registry):
        """Test that the registry starts empty."""
        assert registry.all_tools == {}

    def test_compute_hash_determinism(self, registry):
        """Test that compute_hash is deterministic and ignores key order."""
        tool_def_1 = {
            "name": "test_tool",
            "description": "A test tool",
            "input_schema": {"type": "object", "properties": {"a": 1}},
            "extra_field": "ignore_me",
        }
        tool_def_2 = {
            "extra_field": "ignore_me_too",
            "input_schema": {"type": "object", "properties": {"a": 1}},
            "description": "A test tool",
            "name": "test_tool",
        }

        hash_1 = registry.compute_hash(tool_def_1)
        hash_2 = registry.compute_hash(tool_def_2)

        assert hash_1 == hash_2

        # Verify against manual calculation for a known simple input
        simple_def = {"name": "foo", "description": "bar", "input_schema": {}}
        # Canonical: {"description": "bar", "input_schema": {}, "name": "foo"}
        canonical_json = json.dumps(
            {"description": "bar", "input_schema": {}, "name": "foo"}, sort_keys=True
        ).encode("utf-8")
        expected_hash = hashlib.sha256(canonical_json).hexdigest()
        assert registry.compute_hash(simple_def) == expected_hash

    def test_register_success(self, registry):
        """Test registering a valid tool."""
        tool_def = {"name": "my_tool", "description": "does things", "input_schema": {}}
        metadata = {"source": "test"}

        snapshot = registry.register(tool_def, metadata)

        assert snapshot.name == "my_tool"
        assert snapshot.description == "does things"
        assert snapshot.metadata == metadata
        assert snapshot.definition_hash == registry.compute_hash(tool_def)

        # Verify it's in the registry
        assert "my_tool" in registry.all_tools
        assert registry.get("my_tool") == snapshot

    def test_register_no_overwrite(self, registry):
        """Test that registering an existing tool does NOT overwrite it (TOFU)."""
        # 1. Initial registration
        original_def = {
            "name": "critical_tool",
            "description": "Original benign version",
            "input_schema": {"type": "object"},
        }
        original_snapshot = registry.register(original_def)

        # 2. Attempt overwrite with malicious/different version
        malicious_def = {
            "name": "critical_tool",
            "description": "Malicious hacked version",
            "input_schema": {"type": "object", "properties": {"exploit": True}},
        }
        new_snapshot = registry.register(malicious_def)

        # 3. Assertions
        # The returned snapshot should match the ORIGINAL, not the new one
        assert new_snapshot.description == "Original benign version"
        assert new_snapshot.definition_hash == original_snapshot.definition_hash

        # The registry should still hold the ORIGINAL
        current_snapshot = registry.get("critical_tool")
        assert current_snapshot.description == "Original benign version"
        assert current_snapshot.definition_hash == original_snapshot.definition_hash

    def test_register_missing_name(self, registry):
        """Test that registering a tool without a name raises an error."""
        tool_def = {"description": "nameless tool"}
        with pytest.raises(
            MCPSessionError, match="Cannot register a tool without a name"
        ):
            registry.register(tool_def)

    def test_verify_known_tool(self, registry):
        """Test verify returns True for a known tool."""
        tool_def = {"name": "safe_tool", "input_schema": {}}
        registry.register(tool_def)

        assert registry.verify("safe_tool") is True

    def test_verify_unknown_tool(self, registry):
        """Test verify returns False for an unknown tool."""
        assert registry.verify("ghost_tool") is False

    def test_verify_integrity_check_pass(self, registry):
        """Test verify passes when current definition matches registered hash."""
        tool_def = {"name": "stable_tool", "description": "v1", "input_schema": {}}
        registry.register(tool_def)

        # Exact same definition
        assert registry.verify("stable_tool", tool_def) is True

        # Equivalent definition (different key order, extra fields ignored)
        equiv_def = {
            "name": "stable_tool",
            "input_schema": {},
            "description": "v1",
            "extra": 1,
        }
        assert registry.verify("stable_tool", equiv_def) is True

    def test_verify_integrity_check_fail(self, registry):
        """Test verify fails when current definition doesn't match registered hash."""
        tool_def = {"name": "shifty_tool", "description": "v1", "input_schema": {}}
        registry.register(tool_def)

        # Modified description
        changed_def = {
            "name": "shifty_tool",
            "description": "v2 (hacked)",
            "input_schema": {},
        }
        assert registry.verify("shifty_tool", changed_def) is False

    def test_get_and_all_tools(self, registry):
        """Test retrieving tools via get() and all_tools property."""
        tool_a = {"name": "tool_a"}
        tool_b = {"name": "tool_b"}

        registry.register(tool_a)
        registry.register(tool_b)

        assert len(registry.all_tools) == 2
        assert registry.get("tool_a").name == "tool_a"
        assert registry.get("tool_b").name == "tool_b"
        assert registry.get("tool_c") is None

        # Ensure all_tools returns a copy/readonly-ish view
        # (modifying dict doesn't affect registry)
        tools_view = registry.all_tools
        tools_view["tool_c"] = "fake"
        assert "tool_c" not in registry.all_tools

    def test_initialize_sync_with_api_key(self, monkeypatch):
        """Test that the background worker is initialized when API key is present."""
        monkeypatch.setenv(DECONVOLUTE_API_KEY, "fake-key")

        with patch(
            "deconvolute.core.mcp_session.TelemetrySyncWorker"
        ) as mock_worker_class:
            registry = MCPSessionRegistry("test_server")

            mock_worker_class.assert_called_once_with(registry.store)
            mock_worker_instance = mock_worker_class.return_value
            mock_worker_instance.start.assert_called_once()
            assert registry.worker is mock_worker_instance

    def test_initialize_sync_without_api_key(self, monkeypatch):
        """Test that sync strictly operates offline when no key is configured."""
        monkeypatch.delenv(DECONVOLUTE_API_KEY, raising=False)

        with patch(
            "deconvolute.core.mcp_session.TelemetrySyncWorker"
        ) as mock_worker_class:
            registry = MCPSessionRegistry("test_server")

            mock_worker_class.assert_not_called()
            assert registry.worker is None

    def test_register_pins_and_logs_new_tool(self, registry):
        """
        Test that registering a completely new tool pins it in SQLite and audits it.
        """
        tool_def = {"name": "fresh_tool", "description": "new"}

        with patch.object(registry.store, "get_pinned_hash", return_value=None):
            with patch.object(registry.store, "pin_tool") as mock_pin:
                with patch.object(registry.store, "log_audit_event") as mock_log:
                    registry.register(tool_def)

                    # Compute expected hash manually
                    expected_hash = registry.compute_hash(tool_def)

                    mock_pin.assert_called_once_with(
                        "test_server", 
                        "1.0.0", 
                        "fresh_tool", 
                        expected_hash,
                        agent_id=None,
                    )
                    mock_log.assert_called_once()

                    event_type = mock_log.call_args[1]["event_type"]
                    assert event_type == SecurityEventType.TOOL_PINNED
                    assert mock_log.call_args[1]["agent_id"] is None

    def test_verify_logs_unregistered_tool(self, registry):
        """Test that attempting to verify an unknown tool audits an event."""
        with patch.object(registry.store, "log_audit_event") as mock_log:
            result = registry.verify("ghost_tool")

            assert result is False
            mock_log.assert_called_once()
            assert (
                mock_log.call_args[1]["event_type"]
                == SecurityEventType.UNREGISTERED_ACCESS
            )

    def test_verify_logs_integrity_violation(self, registry):
        """Test that verifying a tampered tool audits a violation."""
        tool_def = {"name": "good_tool", "description": "benign"}
        registry.register(tool_def)

        tampered_def = {"name": "good_tool", "description": "malicious"}

        with patch.object(registry.store, "log_audit_event") as mock_log:
            result = registry.verify("good_tool", tampered_def)

            assert result is False
            mock_log.assert_called_once()
            assert (
                mock_log.call_args[1]["event_type"]
                == SecurityEventType.INTEGRITY_VIOLATION
            )

    def test_register_passes_agent_id_to_store(self):
        """Test that agent_id is forwarded to pin_tool and log_audit_event."""
        registry = MCPSessionRegistry("test_server", "1.0.0", agent_id="agent-42")
        tool_def: ToolInterface = {"name": "tracked_tool", "description": "new"}

        with patch.object(registry.store, "get_pinned_hash", return_value=None):
            with patch.object(registry.store, "pin_tool") as mock_pin:
                with patch.object(registry.store, "log_audit_event") as mock_log:
                    registry.register(tool_def)

                    assert mock_pin.call_args[1]["agent_id"] == "agent-42"
                    assert mock_log.call_args[1]["agent_id"] == "agent-42"

    def test_verify_current_def_none_match(self, registry):
        """
        Test that verify passes when current_def is None and snapshot matches.
        """
        tool_def = {"name": "good_tool", "description": "benign", "input_schema": {}}
        # Register will set definition_hash to compute_hash(tool_def)
        registry.register(tool_def)

        # Execution without passing current_def
        assert registry.verify("good_tool") is True

    def test_verify_current_def_none_mismatch(self, registry):
        """
        Test that verify fails when current_def is None but snapshot hash mismatches.

        This simulates the scenario where a malicious tool was discovered (and saved
        into the snapshot) but we had a locally pinned hash that was different.
        When called without current_def, the registry should reconstruct from the
        snapshot and still detect the mismatch against the definition_hash.
        """
        # Step 1: Pre-pin a "good" trace in the database
        good_def = {"name": "good_tool", "description": "benign", "input_schema": {}}
        good_hash = registry.compute_hash(good_def)

        # We manually pin it so register uses this hash instead of computing from
        # the malicious input
        registry.store.pin_tool(
            registry.server_name, registry.server_version, "good_tool", good_hash
        )

        # Step 2: The server returns a malicious tool definition during list_tools
        malicious_def = {
            "name": "good_tool",
            "description": "malicious",
            "input_schema": {},
        }
        registry.register(malicious_def)

        # The snapshot should now hold the malicious contents, but the good_hash
        snapshot = registry.get("good_tool")
        assert snapshot.definition_hash == good_hash
        assert snapshot.description == "malicious"

        # Step 3: verify during call_tool (current_def is None)
        with patch.object(registry.store, "log_audit_event") as mock_log:
            result = registry.verify("good_tool")

            # Since reconstructs from malicious contents and hashes it != good_hash,
            # should return False
            assert result is False

            # It should have audited the violation
            mock_log.assert_called_once()
            assert (
                mock_log.call_args[1]["event_type"]
                == SecurityEventType.INTEGRITY_VIOLATION
            )
