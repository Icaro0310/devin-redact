"""Offline-core guard: the core must not open sockets.

Release checklist item: "no-network core test (CI): fails if the core
opens a socket". An autouse fixture monkeypatches ``socket.socket.connect``,
``socket.socket.connect_ex`` and ``socket.create_connection`` to raise
``OfflineCoreError`` for the duration of every test in this file, then the
tests run the repo's core operations end to end. This is a guard, not a
mock: any in-process network access fails the suite.

Intentional online paths are excluded by design: secondary-copy installs
are opt-in scheduling only; snapshot create/verify/restore/diff/rotate are
purely local file + SQLite operations. Only in-process sockets are blocked
here.

Opt-out: mark a test ``@pytest.mark.network`` to run it without the socket
block (reserved for tests that intentionally exercise the network).

Run with:
``PYTHONPATH=src:../devin-internals-spec/src python -m pytest tests/test_offline_core.py``
(this repo imports ``devin_internals`` from the sibling checkout).
"""

from __future__ import annotations

import socket

import pytest
from devin_backup import cli


class OfflineCoreError(RuntimeError):
    """Raised when core code tries to open a network connection."""


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


def test_snapshot_create_and_verify_offline(data_dir, backups_dir, capsys):
    """create + verify on the conftest synthetic data dir — all offline."""
    assert cli.main([
        "create", "--data-dir", str(data_dir), "--out", str(backups_dir),
    ]) == 0
    capsys.readouterr()
    snaps = list(backups_dir.iterdir())
    assert len(snaps) == 1 and (snaps[0] / "manifest.json").is_file()

    assert cli.main(["verify", str(snaps[0])]) == 0
    assert "ok" in capsys.readouterr().out.lower()

    assert cli.main(["list", "--out", str(backups_dir)]) == 0
