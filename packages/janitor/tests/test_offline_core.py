"""Offline-core guard: the core must not open sockets.

Release checklist item: "no-network core test (CI): fails if the core
opens a socket". An autouse fixture monkeypatches ``socket.socket.connect``,
``socket.socket.connect_ex`` and ``socket.create_connection`` to raise
``OfflineCoreError`` for the duration of every test in this file, then the
tests run the repo's core operations end to end. This is a guard, not a
mock: any in-process network access fails the suite.

Intentional online paths are excluded by design: ``--judge command:<cmd>``
and ``--export-cmd`` are opt-in subprocess hooks — an in-process socket
block cannot reach subprocess sockets anyway. The core scan/run/report/
pending commands are local-only.

Opt-out: mark a test ``@pytest.mark.network`` to run it without the socket
block (reserved for tests that intentionally exercise the network).

Run with:
``PYTHONPATH=src:../devin-internals-spec/src python -m pytest tests/test_offline_core.py``
(this repo imports ``devin_internals`` from the sibling checkout).
"""

from __future__ import annotations

import json
import socket

import pytest
from conftest import add_gui_session, add_session
from devin_janitor.cli import main


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


@pytest.fixture()
def noisy_dir(devin_dir):
    """A data dir with one deletable noise session + one keeper."""
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    add_session(devin_dir.sessions_db, "work-1", title="real feature work",
                user_msgs=50, tool_calls=40)
    add_gui_session(devin_dir.acp_messages_dir, "gui-noise", title="inbox")
    return devin_dir


def test_socket_block_is_active():
    """Sanity check: the guard itself raises on any connect attempt."""
    with pytest.raises(OfflineCoreError):
        socket.create_connection(("127.0.0.1", 1), timeout=0.01)
    with pytest.raises(OfflineCoreError):
        socket.socket().connect(("127.0.0.1", 1))


def test_report_on_synthetic_data_dir_offline(noisy_dir, tmp_path, capsys):
    """`report` over the conftest data dir — advisory, read-only, offline."""
    rc = main([
        "report",
        "--data-dir", str(noisy_dir.root),
        "--pending-file", str(tmp_path / "pending.json"),
        "--keep-file", str(tmp_path / "keep.json"),
        "--labels-file", str(tmp_path / "no-labels.json"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stores"], "report should cover at least one store"
    assert "totals" in payload


def test_scan_classification_offline(noisy_dir, tmp_path, capsys):
    """`scan` classifies the synthetic sessions without any network."""
    rc = main([
        "scan",
        "--data-dir", str(noisy_dir.root),
        "--keep-file", str(tmp_path / "keep.json"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 3
