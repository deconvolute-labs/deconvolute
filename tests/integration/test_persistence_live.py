import asyncio
import os
import sqlite3
import sys
import tempfile

import pytest
import yaml
from mcp import StdioServerParameters

from deconvolute import secure_stdio_session

# These imports are essential to the tests
from deconvolute.constants import DECONVOLUTE_API_KEY
from deconvolute.core.persistence import DATABASE_NAME
from deconvolute.models.observability import SecurityEventType


@pytest.fixture
def server_script():
    return os.path.join(os.path.dirname(__file__), "mcp_server.py")


@pytest.fixture
def policy_path(server_script):
    policy = {
        "version": "2.0",
        "servers": {
            "live-test-server": {
                "version": ">=0.1.0",
                "transport": {
                    "type": "stdio",
                    "command": sys.executable,
                    "args": [server_script],
                },
                "tools": [
                    {"name": "echo", "action": "allow"},
                    {"name": "add", "action": "allow"},
                ],
            }
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(policy, f)
        path = f.name

    yield path
    os.remove(path)


@pytest.fixture
def server_params(server_script):
    return StdioServerParameters(command=sys.executable, args=[server_script], env=None)


@pytest.mark.asyncio
async def test_state_hydration(isolated_cache_dir, server_params, policy_path):
    """
    Scenario A: State Hydration
    Tests the True 'Trust-On-First-Use' lifecycle across multiple sessions.
    """
    # 1. Session 1 (Discovery): Open session, initialize, list tools, close session.
    async with secure_stdio_session(server_params, policy_path=policy_path) as session:
        await session.initialize()
        await session.list_tools()

    db_path = isolated_cache_dir / DATABASE_NAME

    # 2. Assert 1: Query SQLite DB. Assert tools are pinned and
    # audit_queue has DISCOVERY
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT tool_name FROM pinned_tools WHERE server_name='live-test-server'"
        )
        pinned = {r["tool_name"] for r in cursor.fetchall()}
        assert "echo" in pinned
        assert "add" in pinned

        cursor.execute(
            "SELECT COUNT(*) as count FROM audit_queue WHERE event_type=?",
            (SecurityEventType.TOOL_PINNED,),
        )
        discovery_count_1 = cursor.fetchone()["count"]
        # The telemetry worker hooks in and creates 1 event per tool
        assert discovery_count_1 == 2

    # 3. Session 2 (Hydration): Open second session in exact same DB context.
    async with secure_stdio_session(server_params, policy_path=policy_path) as session:
        await session.initialize()
        await session.list_tools()

    # 4. Assert 2: Assert audit_queue does not contain duplicate TOOL_PINNED events
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) as count FROM audit_queue WHERE event_type=?",
            (SecurityEventType.TOOL_PINNED,),
        )
        discovery_count_2 = cursor.fetchone()["count"]
        # Count should remain 2, proving the tools were hydrated and not re-discovered.
        assert discovery_count_2 == discovery_count_1


@pytest.mark.asyncio
async def test_worker_lifecycle(
    isolated_cache_dir, server_params, policy_path, monkeypatch
):
    """
    Scenario B: Worker Lifecycle
    Guarantee background worker starts when required and stops cleanly without hangs.
    """
    # Inject API Key
    monkeypatch.setenv(DECONVOLUTE_API_KEY, "fake_key_123")
    db_path = isolated_cache_dir / DATABASE_NAME

    async with secure_stdio_session(server_params, policy_path=policy_path) as session:
        await session.initialize()
        # Fire a list tools just in case the firewall lazily connects things
        await session.list_tools()

        worker = session._firewall.registry.worker

        # Assert worker started
        assert worker is not None, "Worker should initialize with DECONVOLUTE_API_KEY"
        assert worker._thread is not None
        assert worker._thread.is_alive()

        # Trigger a security event (UNREGISTERED_ACCESS)
        result = await session.call_tool("haxor_tool", arguments={})
        assert result.isError is True

        # Let the worker catch up to the signal
        await asyncio.sleep(0.2)

    # Prove atexit or context teardown works
    worker.stop()
    if worker._thread:
        worker._thread.join(timeout=2.0)
    assert not worker._thread.is_alive(), "Worker loop failed to terminate on stop()"

    # Finally, verify the event in the database is marked as COMPLETED
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT sync_status FROM audit_queue WHERE event_type=?",
            (SecurityEventType.UNREGISTERED_ACCESS,),
        )
        rows = cursor.fetchall()
        assert len(rows) > 0, "No UNREGISTERED_ACCESS events found"
        for row in rows:
            assert row["sync_status"] == "COMPLETED"
