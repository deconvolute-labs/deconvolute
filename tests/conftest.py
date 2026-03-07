import pytest

from deconvolute.constants import DECONVOLUTE_CACHE_DIR


@pytest.fixture(autouse=True)
def isolated_cache_dir(tmp_path, monkeypatch):
    """
    Global fixture to ensure every test runs with an isolated SQLite database.

    By setting autouse=True, we guarantee that no unit or integration test
    will ever accidentally read from or write to the developer's real
    operating system cache directory.

    Every single test function receives a completely fresh, temporary
    directory, ensuring a blank slate and preventing test cross-contamination.
    """
    monkeypatch.setenv(DECONVOLUTE_CACHE_DIR, str(tmp_path))
    return tmp_path
