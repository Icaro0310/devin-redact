"""MCP adapter contract: do_scan mirrors `scan --json`; the tool layer
exposes scan only — no mutation surface exists to call."""

import json
import tomllib
from pathlib import Path

import pytest

from devin_redact.mcp_server import do_scan

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = [
    FIXTURES / "sessions.db",
    FIXTURES / "memories.jsonl",
    FIXTURES / "export.md",
    FIXTURES / ".env",
]
BENIGN = FIXTURES / "benign.txt"


def test_do_scan_matches_engine_scan():
    from devin_redact import scan

    assert do_scan(scan_paths=[str(p) for p in CORPUS]) == scan(CORPUS)


def test_do_scan_reports_findings_and_status():
    out = do_scan(scan_paths=[str(p) for p in CORPUS])
    assert out["tool"] == "devin-redact"
    assert out["files_scanned"] == len(CORPUS)
    assert out["findings_total"] > 0
    assert out["publication_status"] in {"CLEAN", "REVIEW", "BLOCKED"}


def test_do_scan_clean_file():
    out = do_scan(scan_paths=[str(BENIGN)])
    assert out["publication_status"] == "CLEAN"
    assert out["findings_total"] == 0


def test_do_scan_session_scope():
    out = do_scan(
        sessions_db=str(FIXTURES / "sessions.db"),
        session_id="fixture-session-0001",
    )
    assert out["session_id"] == "fixture-session-0001"
    assert out["files_scanned"] == 1
    assert "publication_status" in out


def test_do_scan_session_missing_db_is_error(tmp_path):
    out = do_scan(
        sessions_db=str(tmp_path / "nope.db"), session_id="anything")
    assert out["error"] == "no_store"


def test_server_exposes_scan_only():
    """The module must not reference the mutation path at all."""
    src = (Path(__file__).parents[1] / "src" / "devin_redact"
           / "mcp_server.py").read_text(encoding="utf-8")
    assert "engine.redact" not in src
    assert "confirm_irreversible" not in src


def test_server_entrypoint_in_pyproject():
    meta = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"))
    assert (meta["project"]["scripts"]["devin-redact-mcp"]
            == "devin_redact.mcp_server:main")
    assert any(dep.startswith("mcp") for dep in
               meta["project"]["optional-dependencies"]["mcp"])


def test_build_server_registers_tool():
    pytest.importorskip("mcp")
    from devin_redact.mcp_server import build_server
    assert build_server() is not None
