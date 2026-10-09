"""RD-2 edge coverage: a secret split at *any* byte offset is detected.

``test_chunked.py`` covers the happy paths; this file sweeps every split
offset of known secret patterns (including 1-char fragments on either
side) and the boundary shapes the pre-filter had to learn to catch:
a token of secret length spanning the boundary, marker prefixes of one
char, and context keywords (``Bearer``, ``KEY=``, ``pairing code``)
hugging the edge.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

import devin_redact

from test_scan import FAKE_API_KEY, FAKE_JWT, _fp

SCHEMA = """
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  working_directory TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  title TEXT
);
CREATE TABLE message_nodes (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  node_id INTEGER NOT NULL,
  chat_message TEXT NOT NULL
);
"""

FAKE_GH = "ghp_" + "FAKE00000000000000000000"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_PEM = (
    "-----BEGIN PRIVATE " + "KEY-----\n"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "-----END PRIVATE " + "KEY-----"
)


def _two_node_db(tmp_path: Path, a: str, b: str, sid_b: str = "s1") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "sessions.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.execute(
        "INSERT INTO sessions VALUES (?,?,?,?,?)", ("s1", "/tmp/p", 1, 2, "t")
    )
    con.execute(
        "INSERT INTO sessions VALUES (?,?,?,?,?)", ("s2", "/tmp/q", 1, 3, "u")
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, chat_message) "
        "VALUES (?,?,?)",
        ("s1", 0, json.dumps({"role": "user", "content": "x " + a})),
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, chat_message) "
        "VALUES (?,?,?)",
        (sid_b, 1, json.dumps({"role": "assistant", "content": b + " y"})),
    )
    con.commit()
    con.close()
    return path


def _fps(report: dict) -> set[str]:
    return {str(f["fingerprint"]) for f in report["findings"]}


def test_secret_split_at_every_byte_offset(tmp_path):
    """Splitting a planted secret at every position is detected."""
    for n, secret in enumerate((FAKE_API_KEY, FAKE_GH, FAKE_AWS, FAKE_JWT)):
        missed = []
        for off in range(1, len(secret)):
            db = _two_node_db(
                tmp_path / f"s{n}o{off}", secret[:off], secret[off:]
            )
            report = devin_redact.scan([db])
            if _fp(secret) not in _fps(report):
                missed.append(off)
        assert missed == [], f"{secret[:8]}… missed at offsets {missed}"


def test_split_with_single_char_fragments(tmp_path):
    # One char on either side of the boundary — no marker survives.
    secret = FAKE_API_KEY
    db = _two_node_db(tmp_path / "a", secret[:1], secret[1:])
    assert _fp(secret) in _fps(devin_redact.scan([db]))
    db = _two_node_db(tmp_path / "b", secret[:-1], secret[-1:])
    assert _fp(secret) in _fps(devin_redact.scan([db]))


def test_env_assignment_split(tmp_path):
    payload = "OPENAI_API_KEY=" + FAKE_API_KEY
    for off in (8, len("OPENAI_API_KEY="), len(payload) - 2):
        db = _two_node_db(tmp_path / f"e{off}", payload[:off], payload[off:])
        report = devin_redact.scan([db])
        assert report["publication_status"] == "BLOCKED", off


def test_bearer_header_split(tmp_path):
    payload = "Authorization: Bearer " + FAKE_JWT
    for off in (len("Authorization: Bearer "), len(payload) // 2,
                len(payload) - 1):
        db = _two_node_db(tmp_path / f"br{off}", payload[:off], payload[off:])
        report = devin_redact.scan([db])
        assert report["publication_status"] == "BLOCKED", off


def test_pem_split_across_payloads(tmp_path):
    off = len(FAKE_PEM) // 2
    db = _two_node_db(tmp_path / "pem", FAKE_PEM[:off], FAKE_PEM[off:])
    report = devin_redact.scan([db])
    assert _fp(FAKE_PEM) in _fps(report)


def test_session_scoped_scan_still_reassembles(tmp_path):
    secret = FAKE_API_KEY
    off = len(secret) // 2
    db = _two_node_db(tmp_path / "scoped", secret[:off], secret[off:])
    report = devin_redact.engine.scan_session(db, "s1")
    assert _fp(secret) in _fps(report)
    assert report["publication_status"] == "BLOCKED"


def test_benign_boundary_token_not_flagged(tmp_path):
    # A long ordinary word crossing the boundary is scanned and ignored.
    word = "pneumonoultramicroscopicsilicovolcanoconiosis"
    off = len(word) // 2
    db = _two_node_db(tmp_path / "benign", word[:off], word[off:])
    report = devin_redact.scan([db])
    boundary_findings = [
        f for f in report["findings"] if "message_nodes" in str(f["location"])
    ]
    assert boundary_findings == []
    assert report["secrets"] == 0


def test_scan_is_still_deterministic(tmp_path):
    secret = FAKE_API_KEY
    off = 7
    db = _two_node_db(tmp_path / "det", secret[:off], secret[off:])
    assert devin_redact.scan([db]) == devin_redact.scan([db])
