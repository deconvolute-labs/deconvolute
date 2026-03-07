import json
import logging
import sqlite3
import threading

from deconvolute.core.persistence import SQLiteStore

logger = logging.getLogger(__name__)


class TelemetrySyncWorker:
    """
    Background worker for syncing audit events to the remote platform.

    Runs in a dedicated daemon thread, waiting for signaling from the
    SQLiteStore. It reads pending events and processes them asynchronously
    without blocking the main application execution.

    Attributes:
        store (SQLiteStore): The local database instance.
    """

    def __init__(self, store: SQLiteStore) -> None:
        """Initializes the sync worker.

        Args:
            store (SQLiteStore): The local database instance containing the
                audit queue and event signal.
        """
        self.store = store
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """
        Starts the background worker thread if not already running.
        """
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="DeconvoluteSyncWorker",
            daemon=True,  # Ensures the thread dies when the main program exits
        )
        self._thread.start()
        logger.debug("Telemetry sync worker started.")

    def stop(self) -> None:
        """
        Signals the worker thread to stop gracefully.
        """
        self._stop_event.set()
        # Trigger the signal so the thread wakes up immediately if it is sleeping
        self.store.new_event_signal.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.debug("Telemetry sync worker stopped.")

    def _run_loop(self) -> None:
        """
        The main execution loop for the background thread.
        """
        while not self._stop_event.is_set():
            # Wait for a signal that new events are available.
            # A timeout acts as a fallback to periodically check for retries.
            self.store.new_event_signal.wait(timeout=60.0)

            if self._stop_event.is_set():
                break

            # Clear the signal so we can catch the next one
            self.store.new_event_signal.clear()
            self._process_pending_events()

    def _process_pending_events(self) -> None:
        """
        Reads pending events from the database and processes them.
        """
        with sqlite3.connect(self.store.db_path) as conn:
            cursor = conn.cursor()
            # Process in batches to keep memory footprint lean
            cursor.execute(
                "SELECT id, event_type, payload FROM audit_queue WHERE "
                "sync_status = 'PENDING' LIMIT 100"
            )
            rows = cursor.fetchall()

            if not rows:
                return

            processed_ids = []
            for row_id, event_type, payload_str in rows:
                _ = json.loads(payload_str)

                # Placeholder for transmission to platform
                # Simulate a successful sync
                logger.debug("Processed event %s: %s", row_id, event_type)
                processed_ids.append(row_id)

            # Update the status of successfully processed rows
            if processed_ids:
                placeholders = ",".join("?" * len(processed_ids))
                query = f"UPDATE audit_queue SET sync_status = 'COMPLETED' WHERE id IN ({placeholders})"  # noqa: E501, S608
                cursor.execute(query, processed_ids)
                conn.commit()
