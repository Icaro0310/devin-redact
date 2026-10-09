"""RD-2: secrets split across adjacent payloads.

A secret streamed in pieces can land split across two adjacent payloads —
half an AWS key at the end of one tool output, the rest at the start of
the next message. The chunked-scan pass re-scans concatenations of
adjacent same-session payloads (``tool_call_json``+``tool_call_update_json``
of the same row, adjacent ``tool_call_state`` rows, adjacent
``message_nodes`` rows, and streaming parts inside one payload) and
reports the reassembled finding at the earlier rowid with
``kind="cross-chunk"``. All values here are synthetic.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

import devin_redact

from test_scan import _fp

# Canonical AWS documentation example key — synthetic by definition.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
HALF_A = FAKE_AWS_KEY[:10]  # AKIA + 6 — too short to match alone
HALF_B = FAKE_AWS_KEY[10:]

SCHEMA = """
CREATE TABLE message_nodes (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  node_id INTEGER NOT NULL,
  chat_message TEXT NOT NULL
);
CREATE TABLE tool_call_state (
    session_id    TEXT    NOT NULL,
    tool_call_id  TEXT    NOT NULL,
    tool_call_json     TEXT,
    tool_call_update_json TEXT,
    PRIMARY KEY (session_id, tool_call_id)
);
"""


def _msg(mid: str, role: str, content: str) -> str:
    return json.dumps({"message_id": mid, "role": role, "content": content})


def _call(tcid: str, command: str) -> str:
    return json.dumps(
        {
            "toolCallId": tcid,
            "kind": "execute",
            "rawInput": {"command": command},
        }
    )


def _update(tcid: str, *texts: str) -> str:
    return json.dumps(
        {
            "toolCallId": tcid,
            "status": "completed",
            "content": [
                {"type": "content", "content": {"type": "text", "text": t}}
                for t in texts
            ],
        }
    )


def _db(tmp_path: Path) -> tuple[Path, sqlite3.Connection]:
    path = tmp_path / "sessions.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    return path, con


def _node(con, session: str, node: int, content: str) -> None:
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, chat_message) "
        "VALUES (?,?,?)",
        (session, node, _msg(f"m-{session}-{node}", "user", content)),
    )


def _call_row(con, session: str, tcid: str, call: str, update: str) -> None:
    con.execute(
        "INSERT INTO tool_call_state VALUES (?,?,?,?)",
        (session, tcid, call, update),
    )


def _cross_chunk(report: dict) -> list[dict]:
    return [f for f in report["findings"] if f.get("kind") == "cross-chunk"]


def _aws_findings(report: dict) -> list[dict]:
    return [
        f
        for f in report["findings"]
        if f["category"] == "api_key" and f["fingerprint"] == _fp(FAKE_AWS_KEY)
    ]


def test_split_secret_across_adjacent_message_nodes(tmp_path):
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "the key begins " + HALF_A)
    _node(con, "s1", 1, HALF_B + " was the rest")
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    assert report["publication_status"] == "BLOCKED"
    aws = _aws_findings(report)
    assert len(aws) == 1
    assert aws[0]["kind"] == "cross-chunk"
    assert aws[0]["location"] == "message_nodes.chat_message#rowid=1"
    assert aws[0]["combined_with"] == "message_nodes.chat_message#rowid=2"


def test_split_secret_across_tool_call_rows(tmp_path):
    db, con = _db(tmp_path)
    _call_row(
        con,
        "s1",
        "tc-a",
        _call("tc-a", "echo first"),
        _update("tc-a", "partial output " + HALF_A),
    )
    _call_row(
        con,
        "s1",
        "tc-b",
        _call("tc-b", "echo second"),
        _update("tc-b", HALF_B + " done"),
    )
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    aws = [f for f in _aws_findings(report) if f["kind"] == "cross-chunk"]
    assert len(aws) == 1
    loc = "tool_call_state.tool_call_json+tool_call_update_json#rowid=1"
    assert aws[0]["location"] == loc
    assert aws[0]["combined_with"] == loc.replace("rowid=1", "rowid=2")


def test_split_secret_within_tool_call_row(tmp_path):
    # The call echoes the first half, its own update starts with the rest.
    db, con = _db(tmp_path)
    _call_row(
        con,
        "s1",
        "tc-x",
        _call("tc-x", "echo " + HALF_A),
        _update("tc-x", HALF_B + " tail"),
    )
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    aws = [f for f in _aws_findings(report) if f["kind"] == "cross-chunk"]
    assert len(aws) == 1
    assert (
        aws[0]["location"]
        == "tool_call_state.tool_call_json+tool_call_update_json#rowid=1"
    )
    assert "combined_with" not in aws[0]


def test_split_secret_inside_streamed_tool_output(tmp_path):
    # Two content parts of the SAME update payload — classic streaming split.
    db, con = _db(tmp_path)
    _call_row(
        con,
        "s1",
        "tc-s",
        _call("tc-s", "curl https://api.example.test"),
        _update("tc-s", "chunk one ends " + HALF_A, HALF_B + " continues"),
    )
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    aws = [f for f in _aws_findings(report) if f["kind"] == "cross-chunk"]
    assert len(aws) == 1
    assert report["publication_status"] == "BLOCKED"


def test_split_across_different_sessions_not_joined(tmp_path):
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "the key begins " + HALF_A)
    _node(con, "s2", 0, HALF_B + " was the rest")
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    assert _aws_findings(report) == []
    assert _cross_chunk(report) == []
    assert report["publication_status"] == "CLEAN"


def test_split_secret_non_adjacent_rows_missed(tmp_path):
    # Only adjacent pairs are scanned — a benign row between the halves
    # keeps them apart (documented bound of the pass).
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "the key begins " + HALF_A)
    _node(con, "s1", 1, "an unrelated message in between")
    _node(con, "s1", 2, HALF_B + " was the rest")
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    assert _aws_findings(report) == []


def test_whole_secret_not_duplicated_as_cross_chunk(tmp_path):
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "whole key: " + FAKE_AWS_KEY)
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    aws = _aws_findings(report)
    assert len(aws) == 1
    assert aws[0]["kind"] == "pattern"  # reported once, as a normal finding
    assert _cross_chunk(report) == []


def test_chunked_scan_is_read_only(tmp_path):
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "the key begins " + HALF_A)
    _node(con, "s1", 1, HALF_B + " was the rest")
    con.commit()
    con.close()

    before = hashlib.sha256(db.read_bytes()).hexdigest()
    devin_redact.scan([db])
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
