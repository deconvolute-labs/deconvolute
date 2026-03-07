import abc
from typing import Any


class BaseObservabilityBackend(abc.ABC):
    """
    Abstract base class for all Deconvolute observability backends.

    A backend is responsible for durably recording security telemetry,
    tool discoveries, integrity violations, and agent execution events.
    """

    @abc.abstractmethod
    def log_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """
        Records a telemetry event to the underlying storage mechanism.

        Args:
            event_type (str): A string categorizing the event
                (e.g. 'TOOL_EXECUTION', 'SCAN_RESULT', 'TOOL_DISCOVERED').
            payload (dict[str, Any]): A dictionary containing the full context
                of the event. This must be JSON serializable.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """
        Cleans up any open resources (like database connections, background
        threads, or file handles) used by the backend before the application exits.
        """
        pass
