import sqlite3
import time
from unittest.mock import patch

import pytest

from deconvolute.constants import DECONVOLUTE_CACHE_DIR
from deconvolute.core.persistence import SQLiteStore
from deconvolute.observability.worker import TelemetrySyncWorker


@pytest.fixture
def temp_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv(DECONVOLUTE_CACHE_DIR, str(tmp_path))
    return tmp_path


@pytest.fixture
def store(temp_cache_dir):
    return SQLiteStore()


@pytest.fixture
def worker(store):
    return TelemetrySyncWorker(store)


def test_worker_initialization(worker, store):
    """
    Test worker initializes properly with stop event cleared.
    """
    assert worker.store is store
    assert not worker._stop_event.is_set()
    assert worker._thread is None


def test_start_and_stop_thread(worker):
    """
    Test that the worker starts the thread and stops it gracefully.
    """
    worker.start()
    assert worker._thread is not None
    assert worker._thread.is_alive()
    assert worker._thread.daemon is True

    # Check stopping
    worker.stop()
    assert not worker._thread.is_alive()


def test_start_already_running(worker):
    """
    Test that calling start() while already running does not spawn a new thread.
    """
    worker.start()
    first_thread = worker._thread

    worker.start()
    assert worker._thread is first_thread

    worker.stop()


def test_stop_signals_store_event(worker):
    """
    Test that stop() sets the stop event and the store's new_event_signal to wake it up.
    """
    # We won't start the thread to isolate the behavior
    worker.stop()
    assert worker._stop_event.is_set()
    assert worker.store.new_event_signal.is_set()


def test_process_pending_events_success(worker, store):
    """
    Test processing of pending events in the queue.
    """
    # Insert some pending events
    payload = {"test": 1}
    store.log_audit_event("EVENT_A", payload)
    store.log_audit_event("EVENT_B", payload)

    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, sync_status FROM audit_queue")
        rows = cursor.fetchall()
        assert len(rows) == 2
        assert all(row[1] == "PENDING" for row in rows)

    worker._process_pending_events()

    # Verify status changed to COMPLETED
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, sync_status FROM audit_queue")
        rows = cursor.fetchall()
        assert len(rows) == 2
        assert all(row[1] == "COMPLETED" for row in rows)


def test_process_pending_events_empty(worker, store):
    """
    Test processing when the queue is empty.
    """
    # No events inserted
    with patch("sqlite3.connect") as mock_connect:
        worker._process_pending_events()
        # It connects to check, but executes a SELECT only, not an UPDATE
        cursor_mock = (
            mock_connect.return_value.__enter__.return_value.cursor.return_value
        )
        cursor_mock.execute.assert_called_once()  # The SELECT statement
        # UPDATE should not be called
        assert cursor_mock.execute.call_count == 1


def test_run_loop_terminates_on_stop(worker):
    """
    Test that the main loop exits when the stop event is set.
    """
    worker._stop_event.set()

    with patch.object(worker, "_process_pending_events") as mock_process:
        worker._run_loop()
        mock_process.assert_not_called()


def test_run_loop_processes_when_signaled(worker, store):
    """
    Test that the loop processes events when the signal is set.
    """

    def simulate_processing():
        # Stop the loop after the first iteration
        worker._stop_event.set()

    with patch.object(
        worker, "_process_pending_events", side_effect=simulate_processing
    ) as mock_process:
        # Signal that a new event arrived
        store.new_event_signal.set()

        worker._run_loop()

        mock_process.assert_called_once()
        # Verify signal was cleared
        assert not store.new_event_signal.is_set()


def test_start_stop_integration(worker, store):
    """
    End-to-end integration test of the worker running alongside event generation.
    """
    worker.start()

    store.log_audit_event("LIVETEST", {"msg": "hello"})

    # Wait for the worker to process
    time.sleep(0.1)

    # Check if the event was set to COMPLETED
    with sqlite3.connect(store.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT sync_status FROM audit_queue WHERE event_type='LIVETEST'"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "COMPLETED"

    worker.stop()
