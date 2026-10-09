"""Offline-core guard: the core must not open sockets.

Release checklist item: "no-network core test (CI): fails if the core
opens a socket". An autouse fixture monkeypatches ``socket.socket.connect``,
``socket.socket.connect_ex`` and ``socket.create_connection`` to raise
``OfflineCoreError`` for the duration of every test in this file, then the
tests run the repo's core operations end to end. This is a guard, not a
mock: any in-process network access fails the suite.

Intentional online paths are excluded by design: none exist in the core —
``scan``/``redact``/``verify``/``gate`` are read-only local file operations.
Only in-process sockets are blocked here.

Opt-out: mark a test ``@pytest.mark.network`` to run it without the socket
block (reserved for tests that intentionally exercise the network).

Run with: ``PYTHONPATH=src python -m pytest tests/test_offline_core.py``
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from devin_redact import cli


class OfflineCoreError(RuntimeError):
    """Raised when core code tries to open a network connection."""


FIXTURES = Path(__file__).parent / "fixtures"


def _offline_fail(*args, **kwargs):
    raise OfflineCoreError("core opened a socket during the offline-core test")


@pytest.fixture(autouse=True)
def _block_sockets(request, monkeypatch):
    """Block all outbound sockets; opt out with ``@pytest.mark.network``."""
    if request.node.get_closest_marker("network"):
        return
    monkeypatch.setattr(socket.socket, "connect", _offline_fail)
    monkeypatch.setattr(socket.socket, "connect_ex", _offline_fail)
    monkeypatch.setattr(socket, "create_connection", _offline_fail)


def test_socket_block_is_active():
    """Sanity check: the guard itself raises on any connect attempt."""
    with pytest.raises(OfflineCoreError):
        socket.create_connection(("127.0.0.1", 1), timeout=0.01)
    with pytest.raises(OfflineCoreError):
        socket.socket().connect(("127.0.0.1", 1))


def test_scan_synthetic_sessions_db_offline(capsys):
    """Read-only scan of the committed synthetic sessions.db fixture."""
    db = FIXTURES / "sessions.db"
    assert db.is_file()

    rc = cli.main(["scan", str(db)])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["files_scanned"] >= 1
    assert report["findings_total"] >= 1  # fixture plants secrets
    assert report["publication_status"] in {"CLEAN", "REVIEW", "BLOCKED"}


def test_gate_and_verify_offline(tmp_path, capsys):
    """verify/gate over the synthetic fixtures — the publication gates."""
    benign = tmp_path / "benign.txt"
    benign.write_text("nothing secret here\n", encoding="utf-8")

    assert cli.main(["verify", str(benign)]) == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out

    capsys.readouterr()
    assert cli.main(["gate", str(FIXTURES / "sessions.db")]) in (0, 1)
    verdict = capsys.readouterr().out.strip()
    assert verdict in {"CLEAN", "REVIEW", "BLOCKED"}
