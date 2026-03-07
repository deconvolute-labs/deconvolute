import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import deconvolute.observability
from deconvolute.constants import DECONVOLUTE_CACHE_DIR
from deconvolute.models.observability import (
    AccessEvent,
    AuditEventType,
    DiscoveryEvent,
    ToolData,
)
from deconvolute.models.security import SecurityStatus
from deconvolute.observability import configure_observability, get_backend
from deconvolute.observability.backends.local import LocalObservabilityBackend


@pytest.fixture(autouse=True)
def reset_backend():
    """Reset the singleton backend before and after each test."""
    deconvolute.observability._active_backend = None
    yield
    deconvolute.observability._active_backend = None


def test_configure_observability_singleton():
    backend = get_backend()
    assert isinstance(backend, LocalObservabilityBackend)

    deconvolute.observability._active_backend = None
    configure_observability()
    assert deconvolute.observability._active_backend is not None


def test_local_observability_backend_writes(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv(DECONVOLUTE_CACHE_DIR, tmpdir)
        backend = LocalObservabilityBackend()

        # Test Discovery Event
        discovery_event = DiscoveryEvent(
            tools_found_count=10,
            tools_allowed_count=5,
            tools_allowed=[
                ToolData(name="tool_a", description="First allowed tool"),
                ToolData(name="tool_b"),
            ],
            tools_blocked=[ToolData(name="tool_c")],
            server_info={"version": "1.0"},
        )
        backend.log_event(
            AuditEventType.TOOL_DISCOVERY, discovery_event.model_dump(mode="json")
        )

        # Test Access Event
        access_event = AccessEvent(
            tool_name="tool_a",
            status=SecurityStatus.SAFE,
            reason="policy_allow",
            metadata={"latency": 0.1},
        )
        backend.log_event(
            AuditEventType.TOOL_EXECUTION, access_event.model_dump(mode="json")
        )

        # Verify Database Content
        db_path = Path(tmpdir) / "deconvolute_state.db"
        assert db_path.exists()

        import sqlite3

        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM audit_queue ORDER BY id ASC").fetchall()

            assert len(rows) == 2
            assert rows[0]["event_type"] == AuditEventType.TOOL_DISCOVERY
            data1 = json.loads(rows[0]["payload"])
            assert data1.get("type") == "discovery" or "tools_found_count" in data1
            assert data1["tools_found_count"] == 10
            assert data1["tools_allowed"][0]["name"] == "tool_a"
            assert data1["tools_allowed"][1]["name"] == "tool_b"

            assert rows[1]["event_type"] == AuditEventType.TOOL_EXECUTION
            data2 = json.loads(rows[1]["payload"])
            assert data2.get("type") == "access" or "tool_name" in data2
            assert data2["tool_name"] == "tool_a"
            assert data2["status"] == "safe"


def test_local_observability_backend_handles_errors(caplog):
    backend = LocalObservabilityBackend()

    with patch.object(
        backend.store, "log_audit_event", side_effect=Exception("DB fully broken")
    ):
        event = AccessEvent(
            tool_name="test",
            status=SecurityStatus.SAFE,
            reason="test",
        )
        # Should not raise exception, but log error
        backend.log_event(AuditEventType.TOOL_EXECUTION, event.model_dump(mode="json"))

    assert (
        "Failed to write audit event 'TOOL_EXECUTION' to SQLite: DB fully broken"
        in caplog.text
    )


def test_tool_data_serialization():
    """Test ToolData model validation and serialization."""
    # Minimum valid
    tool = ToolData(name="minimal")
    assert tool.name == "minimal"
    assert tool.description is None
    assert tool.input_schema == {}
    assert tool.definition_hash is None

    # Full fields
    tool_full = ToolData(
        name="full",
        description="A full tool",
        input_schema={"type": "object"},
        definition_hash="abc123hash",
    )
    data = tool_full.model_dump()
    assert data["name"] == "full"
    assert data["description"] == "A full tool"
    assert data["input_schema"] == {"type": "object"}
    assert data["definition_hash"] == "abc123hash"


def test_discovery_event_validation():
    """Test DiscoveryEvent validation rules."""
    # Valid event
    event = DiscoveryEvent(
        tools_found_count=2,
        tools_allowed_count=1,
        tools_allowed=[ToolData(name="allowed")],
        tools_blocked=[ToolData(name="blocked")],
        server_info={"version": "1.0"},
    )
    assert event.type == "discovery"
    assert len(event.tools_allowed) == 1
    assert len(event.tools_blocked) == 1

    # Invalid tool type in list
    with pytest.raises(ValidationError):
        DiscoveryEvent(
            tools_found_count=1,
            tools_allowed_count=0,
            tools_allowed=["not_a_tool_data"],  # type: ignore
            tools_blocked=[],
        )


def test_access_event_serialization():
    """Test AccessEvent serialization with metadata."""
    event = AccessEvent(
        tool_name="test_tool",
        status=SecurityStatus.UNSAFE,
        reason="integrity_violation",
        metadata={
            "expected_hash": "abc",
            "actual_hash": "def",
            "offending_definition": ToolData(name="test_tool").model_dump(),
        },
    )

    json_str = event.model_dump_json()
    data = json.loads(json_str)

    assert data["type"] == "access"
    assert data["tool_name"] == "test_tool"
    assert data["status"] == "unsafe"
    assert data["metadata"]["expected_hash"] == "abc"
    assert data["metadata"]["offending_definition"]["name"] == "test_tool"


def test_event_timestamps():
    """Ensure events have valid UTC timestamps by default."""
    event = DiscoveryEvent(
        tools_found_count=0,
        tools_allowed_count=0,
        tools_allowed=[],
        tools_blocked=[],
    )
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None  # Should be aware (UTC)
