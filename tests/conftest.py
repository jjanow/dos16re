import pytest


@pytest.fixture(autouse=True)
def _private_worker_dir(tmp_path_factory, monkeypatch):
    """Keep worker sockets per test, so no worker outside the test session answers a test's queries."""
    directory = tmp_path_factory.mktemp("w", numbered=True)
    directory.chmod(0o700)
    monkeypatch.setenv("RETRORE_WORKER_DIR", str(directory))
    monkeypatch.delenv("RETRORE_WORKER", raising=False)
    monkeypatch.delenv("RETRORE_WORKER_IDLE", raising=False)
