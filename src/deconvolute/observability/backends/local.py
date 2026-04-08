from typing import Any

from deconvolute.core.persistence import SQLiteStore
from deconvolute.observability.base import BaseObservabilityBackend
from deconvolute.utils.logger import get_logger

logger = get_logger()


class LocalObservabilityBackend(BaseObservabilityBackend):
    """
    A unified local observability backend powered by SQLite.

    All security telemetry, tool discoveries, and agent execution logs are
    written to the `audit_queue` table. If an API key is present, the background
    worker will securely transmit these events to the remote platform.
    If not, they are retained locally with a cap to prevent disk bloat.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initializes the SQLite-backed local observability layer.
        """
        super().__init__(*args, **kwargs)
        self.store = SQLiteStore()
        logger.debug("Initialized LocalObservabilityBackend with SQLite storage.")

    def log_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        agent_id: str | None = None,
    ) -> None:
        """
        Records a telemetry event to the database.

        Args:
            event_type (str): Categorizes the event (e.g. 'SESSION_DISCOVERY',
                'SESSION_ACCESS').
            payload (dict[str, Any]): The full contextual payload to record.
            agent_id (str | None, optional): An optional identifier for the agent
                that produced the event. Defaults to None.
        """
        try:
            self.store.log_audit_event(
                event_type=event_type, payload=payload, agent_id=agent_id
            )
        except Exception as e:
            # We never want a failure in telemetry to crash the user's main application
            logger.error(f"Failed to write audit event '{event_type}' to SQLite: {e}")

    def close(self) -> None:
        """
        Cleans up resources.
        SQLite connections are handled via context managers in the store,
        so no explicit teardown is strictly required here.
        """
        pass
