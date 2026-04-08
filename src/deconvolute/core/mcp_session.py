import atexit
import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from deconvolute.constants import DECONVOLUTE_API_KEY
from deconvolute.core.persistence import SQLiteStore
from deconvolute.core.types import ToolInterface
from deconvolute.errors import MCPSessionError
from deconvolute.models.observability import SecurityEventType
from deconvolute.observability.worker import TelemetrySyncWorker
from deconvolute.utils.logger import get_logger

logger = get_logger()


class ToolSnapshot(BaseModel):
    """
    Represents the 'Sealed' state of a tool at the moment of discovery.

    This object is immutable. It serves as the authoritative record of
    what a tool looked like when it was approved by the policy.
    """

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="The JSON schema defining the tool's arguments.",
    )
    definition_hash: str = Field(
        ..., description="SHA-256 hash of the canonicalized tool definition."
    )
    server_version: str = Field(
        ..., description="The reported version of the server that registered this tool."
    )
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this tool was registered.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary context (e.g. server_name, source_file).",
    )

    # Immutable to prevent tampering after creation
    model_config = ConfigDict(frozen=True)


class MCPSessionRegistry:
    """
    The Authority for the current MCP Session.

    It acts as a trusted registry of all tools that have been discovered
    and allowed by the Firewall. It provides O(1) lookups to verify
    tool integrity during execution while backing state to a local SQLite database.
    """

    def __init__(
        self,
        server_name: str | None = None,
        server_version: str | None = None,
        agent_id: str | None = None,
    ) -> None:
        """
        Initializes the MCP session registry.

        Args:
            server_name (str | None): The identifier of the connected MCP server.
            server_version (str | None): The reported version of the MCP server.
            agent_id (str | None): An optional identifier for the agent using
                this registry. Stored with every audit event and pinned tool.
        """
        self.server_name = server_name
        self.server_version = server_version
        self.agent_id = agent_id
        self.store = SQLiteStore()
        # The primary storage: Maps tool_name -> ToolSnapshot
        self._tools: dict[str, ToolSnapshot] = {}
        self.worker: TelemetrySyncWorker | None = None
        self._initialize_sync()

    def _initialize_sync(self) -> None:
        """
        Starts the background sync if platform credentials are present.
        """
        api_key = os.environ.get(DECONVOLUTE_API_KEY)

        if api_key:
            logger.debug("API Key detected. Initializing remote telemetry sync.")
            self.worker = TelemetrySyncWorker(self.store)
            self.worker.start()

            # Ensure the thread shuts down cleanly when the application exits
            atexit.register(self.worker.stop)
        else:
            logger.info(
                "No DECONVOLUTE_API_KEY found. Operating in local offline mode. "
                "Audit events will be capped at 10000 records."
            )

    def set_server_name(self, server_name: str, server_version: str) -> None:
        """Sets the server name and version once discovered by the firewall."""
        self.server_name = server_name
        self.server_version = server_version

    def compute_hash(self, tool_def: ToolInterface) -> str:
        """
        Computes a deterministic SHA-256 hash of a tool definition.

        We canonicalize the data by:
        1. Extracting only functional fields (name, description, inputSchema).
        2. Sorting dictionary keys to ensure {a:1, b:2} == {b:2, a:1}.

        Args:
            tool_def: The tool definition dictionary to hash.

        Returns:
            The SHA-256 hash string of the canonicalized tool definition.
        """
        # This is more stable than a Pydantic model because we control the dict.
        canonical_data = {
            "name": tool_def.get("name"),
            "description": tool_def.get("description"),
            "input_schema": tool_def.get("input_schema"),
        }
        # sort_keys=True is CRITICAL for consistency across Python versions/platforms
        json_byte_string = json.dumps(canonical_data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(json_byte_string).hexdigest()

    def register(
        self, tool_def: ToolInterface, metadata: dict[str, Any] | None = None
    ) -> ToolSnapshot:
        """
        Registers a tool into the session by establishing its authoritative baseline.

        Implements Trust-On-First-Use (TOFU) backed by persistent SQLite storage.
        If a tool is already registered in memory, it is skipped. If it is new
        to the session, it checks the persistent baseline. If unknown globally,
        it is pinned and an audit event is generated.

        Args:
            tool_def (ToolInterface): The raw dictionary from the MCP 'list_tools'
                response.
            metadata (dict[str, Any] | None, optional): Optional extra context to
                attach to the snapshot. Defaults to None.

        Returns:
            ToolSnapshot: The created ToolSnapshot object.

        Raises:
            MCPSessionError: If the tool definition is missing a name.
        """
        name = tool_def.get("name")
        if not name:
            raise MCPSessionError("Cannot register a tool without a name.")
        if not self.server_name or not self.server_version:
            raise MCPSessionError(
                "Cannot register a tool without a complete server identity."
            )

        # In-memory check: skip if we already loaded it this session
        # Trust On First Use
        # If we have seen this tool before, we refuse to update the definition.
        # This ensures our snapshot remains pinned to the benign state.
        if name in self._tools:
            logger.debug(
                f"SessionRegistry: Ignoring update for pinned tool '{name}'. "
                "Keeping original snapshot."
            )
            return self._tools[name]

        tool_hash = self.compute_hash(tool_def)
        pinned_hash = self.store.get_pinned_hash(
            self.server_name, self.server_version, name
        )

        if pinned_hash is None:
            # First time seeing this tool across ANY session for this server.
            logger.info(f"Discovering and pinning new tool: {name}")
            self.store.pin_tool(
                self.server_name, 
                self.server_version, 
                name, 
                tool_hash,
                agent_id=self.agent_id,
            )
            self.store.log_audit_event(
                event_type=SecurityEventType.TOOL_PINNED,
                payload={
                    "server_name": self.server_name,
                    "server_version": self.server_version,
                    "tool_name": name,
                    "schema_hash": tool_hash,
                    "schema": tool_def,
                    "message": "New tool discovered and pinned locally.",
                },
                agent_id=self.agent_id,
            )
            # The baseline is the newly calculated hash
            expected_hash = tool_hash
        else:
            # We have a historical baseline. Use the persistent hash, regardless
            # of what the current tool definition looks like.
            expected_hash = pinned_hash

        snapshot = ToolSnapshot(
            name=name,
            description=tool_def.get("description"),
            input_schema=tool_def.get("input_schema", {}),
            definition_hash=expected_hash,
            server_version=self.server_version,
            metadata=metadata or {},
        )

        self._tools[name] = snapshot
        logger.debug(
            f"SessionRegistry: Registered tool '{name}' (Hash: {tool_hash[:8]})"
        )
        return snapshot

    def verify(self, tool_name: str, current_def: ToolInterface | None = None) -> bool:
        """
        Verifies the integrity of a tool against the authoritative session snapshot.

        Args:
            tool_name (str): The name of the tool being called.
            current_def (ToolInterface | None, optional): The current definition of
                the tool. If provided, we re-hash it to detect tampering. Defaults
                to None.

        Returns:
            bool: True if the tool is known and matches the authoritative hash.
                False if the tool is unknown or has been tampered with.
        """
        if not self.server_name:
            logger.error("Attempted to verify tool before server name was set.")
            return False
        snapshot = self._tools.get(tool_name)

        # Unknown tool check (shadowing / hallucination)
        if not snapshot:
            logger.warning(f"SessionRegistry: Tool '{tool_name}' is not registered.")
            self.store.log_audit_event(
                event_type=SecurityEventType.UNREGISTERED_ACCESS,
                payload={
                    "server_name": self.server_name,
                    "server_version": self.server_version,
                    "tool_name": tool_name,
                    "message": "Execution attempted for a tool that was never "
                    "registered.",
                },
                agent_id=self.agent_id,
            )
            return False

        # Reconstruct the definition if not provided (e.g. during tool execution)
        # Since `register` stores whatever the server provided during discovery,
        # snapshot.input_schema holds the malicious payload if an attack occurred.
        def_to_check = current_def or {
            "name": snapshot.name,
            "description": snapshot.description,
            "input_schema": snapshot.input_schema,
        }

        # Integrity check (rug pull)
        current_hash = self.compute_hash(def_to_check)

        if current_hash != snapshot.definition_hash:
            logger.warning(
                f"SessionRegistry: INTEGRITY FAILURE for '{tool_name}'. "
                f"Expected {snapshot.definition_hash[:8]}, got {current_hash[:8]}."
            )
            self.store.log_audit_event(
                event_type=SecurityEventType.INTEGRITY_VIOLATION,
                payload={
                    "server_name": self.server_name,
                    "server_version": self.server_version,
                    "tool_name": tool_name,
                    "expected_hash": snapshot.definition_hash,
                    "actual_hash": current_hash,
                    "schema": def_to_check,
                    "message": (
                        "Tool schema hash does not match the authoritative baseline."
                    ),
                },
                agent_id=self.agent_id,
            )
            return False

        return True

    def get(self, tool_name: str) -> ToolSnapshot | None:
        """Retrieve a snapshot by name."""
        return self._tools.get(tool_name)

    @property
    def all_tools(self) -> dict[str, ToolSnapshot]:
        """Returns a read-only view of all registered tools."""
        return self._tools.copy()
