import json
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import platformdirs

from deconvolute.constants import DECONVOLUTE_CACHE_DIR

APP_NAME = "deconvolute"
DATABASE_NAME = "deconvolute_state.db"


class SQLiteStore:
    """
    Manages local SQLite persistence for session state and audit telemetry.

    This class handles the initialization and interaction with the local
    SQLite database. It maintains the authoritative state of pinned tools
    and buffers outbound security events for background synchronization.

    Attributes:
        db_path (Path): The absolute path to the local SQLite database file.
        new_event_signal (threading.Event): A thread-safe flag used to signal
            background workers when a new event is added to the audit queue.
    """

    def __init__(self) -> None:
        """
        Initializes the SQLiteStore, resolves paths, and prepares tables.
        """
        self.db_path = self._resolve_db_path()
        self.new_event_signal = threading.Event()
        self._init_db()

    def _resolve_db_path(self) -> Path:
        """
        Determines the correct file path for the SQLite database.

        Checks the environment variable 'DECONVOLUTE_CACHE_DIR' first. If not
        set, it falls back to the standard OS-specific user cache directory.

        Returns:
            Path: The fully resolved path to the database file.
        """
        env_dir = os.environ.get(DECONVOLUTE_CACHE_DIR)
        if env_dir:
            base_dir = Path(env_dir)
        else:
            # Resolves to standard paths like ~/.cache/deconvolute on Linux
            # or AppData/Local/deconvolute/Cache on Windows.
            base_dir = Path(platformdirs.user_cache_dir(appname=APP_NAME))

        base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir / DATABASE_NAME

    def _init_db(self) -> None:
        """
        Creates the required database tables if they do not already exist.

        Sets up 'pinned_tools' for local integrity state and 'audit_queue'
        for outbound security telemetry.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Table 1: Inbound / Local State
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pinned_tools (
                    server_name TEXT,
                    server_version TEXT,
                    tool_name TEXT,
                    schema_hash TEXT,
                    discovered_at TIMESTAMP,
                    updated_from_remote BOOLEAN,
                    agent_id TEXT,
                    PRIMARY KEY (server_name, server_version, tool_name)
                )
            """)

            # Table 2: Outbound / Telemetry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    payload TEXT,
                    created_at TIMESTAMP,
                    sync_status TEXT DEFAULT 'PENDING',
                    retry_count INTEGER DEFAULT 0,
                    agent_id TEXT
                )
            """)

            # Auto-cleanup Trigger: Keep only the latest 10000 events.
            # Using max(id) is highly optimized in SQLite.
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS enforce_audit_queue_limit
                AFTER INSERT ON audit_queue
                BEGIN
                    DELETE FROM audit_queue 
                    WHERE id <= (SELECT max(id) - 10000 FROM audit_queue);
                END;
            """)

            conn.commit()

    def pin_tool(
        self,
        server_name: str,
        server_version: str,
        tool_name: str,
        schema_hash: str,
        from_remote: bool = False,
        agent_id: str | None = None,
    ) -> None:
        """
        Updates the local integrity baseline for a specific tool.

        If the tool already exists for the given server and version,
        its hash and timestamp are overwritten. Otherwise, a new record is created.

        Args:
            server_name (str): The identifier of the MCP server providing the tool.
            server_version (str): The reported version of the MCP server.
            tool_name (str): The name of the tool being pinned.
            schema_hash (str): The cryptographic hash of the tool's schema.
            from_remote (bool, optional): Indicates if the hash was downloaded
                from the platform. Defaults to False.
            agent_id (str | None, optional): An optional identifier for the agent
                that pinned the tool. Defaults to None.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            now = datetime.now(UTC).isoformat()
            cursor.execute(
                """
                INSERT INTO pinned_tools (
                    server_name,
                    server_version,
                    tool_name,
                    schema_hash,
                    discovered_at,
                    updated_from_remote,
                    agent_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_name, server_version, tool_name) DO UPDATE SET
                    schema_hash=excluded.schema_hash,
                    discovered_at=excluded.discovered_at,
                    updated_from_remote=excluded.updated_from_remote,
                    agent_id=excluded.agent_id
            """,
                (
                    server_name,
                    server_version,
                    tool_name,
                    schema_hash,
                    now,
                    from_remote,
                    agent_id,
                ),
            )
            conn.commit()

    def get_pinned_hash(
        self, server_name: str, server_version: str, tool_name: str
    ) -> str | None:
        """
        Retrieves the expected schema hash for a given tool.

        Args:
            server_name (str): The identifier of the MCP server.
            server_version (str): The version of the MCP server.
            tool_name (str): The name of the tool.

        Returns:
            str | None: The expected hash string if found, or None if the tool
                has not been pinned yet.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT schema_hash FROM pinned_tools WHERE server_name = ? AND "
                "server_version = ? AND tool_name = ?",
                (server_name, server_version, tool_name),
            )
            row = cursor.fetchone()
            return row[0] if row else None

    def log_audit_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        agent_id: str | None = None,
    ) -> None:
        """
        Records a security event and wakes up the background sync worker.

        Args:
            event_type (str): Categorizes the event (e.g. 'TOOL_PINNED').
            payload (dict): A dictionary containing the full context of the event,
                which will be serialized to JSON.
            agent_id (str | None, optional): An optional identifier for the agent
                that produced the event. Defaults to None.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            now = datetime.now(UTC).isoformat()
            cursor.execute(
                """
                INSERT INTO audit_queue (event_type, payload, created_at, agent_id)
                VALUES (?, ?, ?, ?)
            """,
                (event_type, json.dumps(payload), now, agent_id),
            )
            conn.commit()

        # Signal the background thread that new data is ready
        self.new_event_signal.set()
