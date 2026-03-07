import json
import sqlite3
from datetime import UTC, datetime

import pytest

from deconvolute.constants import DECONVOLUTE_CACHE_DIR
from deconvolute.core.persistence import APP_NAME, DATABASE_NAME, SQLiteStore


@pytest.fixture
def store():
    """Provides a fresh SQLiteStore instance backed by a temporary directory."""
    return SQLiteStore()


def test_resolve_db_path(isolated_cache_dir):
    """Ensures db_path resolves correctly with the environment variable."""
    store = SQLiteStore()
    expected_path = isolated_cache_dir / DATABASE_NAME
    assert store.db_path == expected_path


def test_resolve_db_path_no_env_var(monkeypatch, tmp_path):
    """Ensures db_path falls back to platformdirs."""
    monkeypatch.delenv(DECONVOLUTE_CACHE_DIR, raising=False)

    # Mock platformdirs to point to our test directory
    def mock_user_cache_dir(appname=None):
        return str(tmp_path / appname)

    monkeypatch.setattr("platformdirs.user_cache_dir", mock_user_cache_dir)

    store = SQLiteStore()
    expected_path = tmp_path / APP_NAME / DATABASE_NAME
    assert store.db_path == expected_path


def test_init_db_creates_tables(store):
    """Ensures that the required tables are created during initialization."""
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()

        # Check pinned_tools
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='pinned_tools'"
        )
        assert cursor.fetchone() is not None

        # Check audit_queue
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_queue'"
        )
        assert cursor.fetchone() is not None


def test_pin_tool_inserts_new_record(store):
    """Ensures that a new tool is properly pinned."""
    store.pin_tool("server_one", "my_tool", "hash123")

    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM pinned_tools WHERE server_name='server_one' AND "
            "tool_name='my_tool'"
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["schema_hash"] == "hash123"
        assert row["updated_from_remote"] == 0
        # Check timestamp
        timestamp = datetime.fromisoformat(row["discovered_at"])
        assert timestamp.tzinfo is not None  # Aware datetime (UTC)


def test_pin_tool_updates_existing_record(store):
    """
    Ensures that an existing pinned tool updates correctly without constraint error.
    """
    store.pin_tool("server_one", "my_tool", "hash123")
    store.pin_tool("server_one", "my_tool", "hash456", from_remote=True)

    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM pinned_tools WHERE server_name='server_one' AND "
            "tool_name='my_tool'"
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["schema_hash"] == "hash456"
        assert row["updated_from_remote"] == 1

        # Ensure only 1 record exists
        cursor.execute("SELECT COUNT(*) as count FROM pinned_tools")
        assert cursor.fetchone()["count"] == 1


def test_get_pinned_hash(store):
    """Ensures retrieving hash works correctly for both existing and missing records."""
    assert store.get_pinned_hash("srv", "tool") is None

    store.pin_tool("srv", "tool", "abcd")
    assert store.get_pinned_hash("srv", "tool") == "abcd"
    assert store.get_pinned_hash("srv", "other") is None
    assert store.get_pinned_hash("other_srv", "tool") is None


def test_log_audit_event(store):
    """
    Ensures audit events are properly serialized and inserted, and the event signal
    is set.
    """
    assert not store.new_event_signal.is_set()

    payload = {"user": "Alice", "action": "test"}
    store.log_audit_event("TEST_EVENT", payload)

    assert store.new_event_signal.is_set()

    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_queue")
        row = cursor.fetchone()

        assert row is not None
        assert row["event_type"] == "TEST_EVENT"
        assert json.loads(row["payload"]) == payload
        assert row["sync_status"] == "PENDING"
        assert row["retry_count"] == 0


def test_audit_queue_truncation(store):
    """
    Ensures the auto-cleanup trigger correctly prevents the queue from exceeding
    10000 records.
    """
    store.log_audit_event("FILLER", {"data": "..."})

    # Manually insert 10005 records faster without log_audit_event overhead
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        data = [
            ("BULK", json.dumps({}), datetime.now(UTC).isoformat())
            for _ in range(10005)
        ]
        cursor.executemany(
            "INSERT INTO audit_queue (event_type, payload, created_at) "
            "VALUES (?, ?, ?)",
            data,
        )
        conn.commit()

    # 1 from log_audit_event + 10005 bulk = 10006 inserted over all, but trigger
    # deletes everything except the last 10000
    # The max ID is 10006. Max - 10000 = 6. So rows 1 to 6 should be deleted.
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_queue")
        count = cursor.fetchone()[0]

        assert count == 10000
