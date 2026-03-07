from deconvolute.observability.backends.local import LocalObservabilityBackend
from deconvolute.observability.base import BaseObservabilityBackend
from deconvolute.utils.logger import get_logger

logger = get_logger()

# Global singleton for the active observability backend
_active_backend: BaseObservabilityBackend | None = None


def configure_observability() -> None:
    """
    Initializes the global observability backend.

    This sets up the local SQLite outbox for telemetry and starts the
    background synchronization worker if platform credentials are provided.
    """
    global _active_backend
    if _active_backend is None:
        _active_backend = LocalObservabilityBackend()
        logger.debug(
            "Observability configured with SQLite-backed LocalObservabilityBackend."
        )


def get_backend() -> BaseObservabilityBackend:
    """Retrieves the active observability backend, initializing it if necessary."""
    global _active_backend
    if _active_backend is None:
        configure_observability()

    # We can safely ignore the type checker here because configure_observability
    # guarantees _active_backend is no longer None.
    return _active_backend  # type: ignore
