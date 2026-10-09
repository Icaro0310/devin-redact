"""RD-1: ``devin-redact session-end`` — the SessionEnd scan hook.

Resolves the just-ended session (``--session-id`` → ``{"session_id": …}``
on stdin → ``DEVIN_SESSION_ID`` → most recently active in ``sessions.db``),
scans only that session's rows and writes the verdict to a side file under
``<data-dir>/redact/<session-id>.json``. Fail-soft: unresolvable sessions
produce a ``SKIPPED`` verdict and exit 0; the hook never writes into any
Devin store or transcript.
"""

import hashlib
import io
import json
import sqlite3
from pathlib import Path

import devin_redact
from devin_redact import cli, session_end
from test_scan import FAKE_API_KEY, _fp

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
CREATE TABLE prompt_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  session_id TEXT NOT NULL
);
"""

CLEAN_SID = "sess-clean"
DIRTY_SID = "sess-dirty"
RECENT_SID = "sess-recent"


def _msg(role: str, content: str) -> str:
    return json.dumps({"role": role, "content": content})


def _db(tmp_path: Path) -> Path:
    """A sessions.db-shaped store with three sessions.

    ``sess-dirty`` leaks an api key in a message, ``sess-recent`` leaks a
    pairing code in prompt history and is the most recently active,
    ``sess-clean`` has no findings.
    """
    path = tmp_path / "sessions.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.executemany(
        "INSERT INTO sessions VALUES (?,?,?,?,?)",
        [
            (CLEAN_SID, "/tmp/clean", 100, 200, "clean"),
            (DIRTY_SID, "/tmp/dirty", 100, 300, "dirty"),
            (RECENT_SID, "/tmp/recent", 100, 400, "recent"),
        ],
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, chat_message) "
        "VALUES (?,?,?)",
        (DIRTY_SID, 0, _msg("user", "my key is " + FAKE_API_KEY)),
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, chat_message) "
        "VALUES (?,?,?)",
        (CLEAN_SID, 0, _msg("user", "nothing sensitive")),
    )
    con.execute(
        "INSERT INTO prompt_history (content, timestamp, session_id) "
        "VALUES (?,?,?)",
        ("devin pairing code: FAKE-1234-ABCD", 500, RECENT_SID),
    )
    con.commit()
    con.close()
    return path


def _verdict_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run(argv, monkeypatch, stdin_text=None):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text or ""))
    return cli.main(argv)


# --- resolution chain ------------------------------------------------------


def test_session_id_flag_scans_that_session(tmp_path, monkeypatch):
    db = _db(tmp_path)
    data = tmp_path / "data"
    code = _run(
        ["session-end", "--session-id", DIRTY_SID, "--sessions-db", str(db),
         "--data-dir", str(data)],
        monkeypatch,
    )
    assert code == 0
    verdict = _verdict_file(data / "redact" / f"{DIRTY_SID}.json")
    assert verdict["publication_status"] == "BLOCKED"
    assert verdict["session_id"] == DIRTY_SID
    assert verdict["session_id_source"] == "flag"
    fps = {f["fingerprint"] for f in verdict["findings"]}
    assert _fp(FAKE_API_KEY) in fps


def test_stdin_json_payload_resolution(tmp_path, monkeypatch):
    db = _db(tmp_path)
    data = tmp_path / "data"
    code = _run(
        ["session-end", "--sessions-db", str(db), "--data-dir", str(data)],
        monkeypatch,
        stdin_text=f'{{"session_id": "{DIRTY_SID}", "hook": "SessionEnd"}}',
    )
    assert code == 0
    verdict = _verdict_file(data / "redact" / f"{DIRTY_SID}.json")
    assert verdict["session_id"] == DIRTY_SID
    assert verdict["session_id_source"] == "stdin"
    assert verdict["publication_status"] == "BLOCKED"


def test_env_var_resolution(tmp_path, monkeypatch):
    db = _db(tmp_path)
    data = tmp_path / "data"
    monkeypatch.setenv("DEVIN_SESSION_ID", RECENT_SID)
    code = _run(
        ["session-end", "--sessions-db", str(db), "--data-dir", str(data)],
        monkeypatch,
    )
    assert code == 0
    verdict = _verdict_file(data / "redact" / f"{RECENT_SID}.json")
    assert verdict["session_id"] == RECENT_SID
    assert verdict["session_id_source"] == "env"
    assert verdict["publication_status"] == "BLOCKED"
    cats = {f["category"] for f in verdict["findings"]}
    assert "devin_pairing_code" in cats


def test_latest_active_fallback(tmp_path, monkeypatch):
    db = _db(tmp_path)
    data = tmp_path / "data"
    monkeypatch.delenv("DEVIN_SESSION_ID", raising=False)
    code = _run(
        ["session-end", "--sessions-db", str(db), "--data-dir", str(data)],
        monkeypatch,
    )
    assert code == 0
    verdict = _verdict_file(data / "redact" / f"{RECENT_SID}.json")
    assert verdict["session_id"] == RECENT_SID
    assert verdict["session_id_source"] == "latest"


def test_flag_beats_stdin_beats_env_beats_latest(tmp_path, monkeypatch):
    db = _db(tmp_path)
    monkeypatch.setenv("DEVIN_SESSION_ID", RECENT_SID)
    # flag wins over stdin and env
    sid, src = session_end.resolve_session_id(
        flag="s-flag",
        stdin_text='{"session_id": "s-stdin"}',
        environ={"DEVIN_SESSION_ID": "s-env"},
        db_path=db,
    )
    assert (sid, src) == ("s-flag", "flag")
    # stdin wins over env and latest
    sid, src = session_end.resolve_session_id(
        flag=None,
        stdin_text='{"session_id": "s-stdin"}',
        environ={"DEVIN_SESSION_ID": "s-env"},
        db_path=db,
    )
    assert (sid, src) == ("s-stdin", "stdin")
    # env wins over latest
    sid, src = session_end.resolve_session_id(
        flag=None, stdin_text=None, environ={"DEVIN_SESSION_ID": "s-env"},
        db_path=db,
    )
    assert (sid, src) == ("s-env", "env")
    # invalid stdin falls through to env
    sid, src = session_end.resolve_session_id(
        flag=None, stdin_text="not json", environ={"DEVIN_SESSION_ID": "s-env"},
        db_path=db,
    )
    assert (sid, src) == ("s-env", "env")


# --- verdicts ---------------------------------------------------------------

def test_clean_session_verdict(tmp_path, monkeypatch):
    db = _db(tmp_path)
    out = tmp_path / "verdict.json"
    code = _run(
        ["session-end", "--session-id", CLEAN_SID, "--sessions-db", str(db),
         "--out", str(out)],
        monkeypatch,
    )
    assert code == 0
    verdict = _verdict_file(out)
    assert verdict["publication_status"] == "CLEAN"
    assert verdict["findings"] == []


def test_session_scope_excludes_other_sessions(tmp_path, monkeypatch):
    db = _db(tmp_path)
    verdict = session_end.run_hook(
        session_id=CLEAN_SID,
        sessions_db=db,
        data_dir=tmp_path / "data",
        environ={},
    )
    assert verdict["publication_status"] == "CLEAN"
    assert _fp(FAKE_API_KEY) not in {
        f["fingerprint"] for f in verdict["findings"]
    }


def test_blocked_still_exits_zero(tmp_path, monkeypatch, capsys):
    db = _db(tmp_path)
    code = _run(
        ["session-end", "--session-id", DIRTY_SID, "--sessions-db", str(db),
         "--data-dir", str(tmp_path / "data")],
        monkeypatch,
    )
    assert code == 0  # a hook must never block session teardown
    out = capsys.readouterr().out
    assert "publication_status=BLOCKED" in out
    assert FAKE_API_KEY not in out  # verdict line never leaks the secret


# --- fail-soft SKIPPED paths -------------------------------------------------


def test_unknown_session_id_is_skipped(tmp_path, monkeypatch):
    db = _db(tmp_path)
    out = tmp_path / "v.json"
    code = _run(
        ["session-end", "--session-id", "no-such-session",
         "--sessions-db", str(db), "--out", str(out)],
        monkeypatch,
    )
    assert code == 0
    verdict = _verdict_file(out)
    assert verdict["publication_status"] == "SKIPPED"
    assert "not found" in verdict["reason"]


def test_no_sessions_db_is_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("DEVIN_SESSION_ID", raising=False)
    out = tmp_path / "v.json"
    code = _run(
        ["session-end", "--sessions-db", str(tmp_path / "none"),
         "--out", str(out)],
        monkeypatch,
    )
    # A --sessions-db path that does not exist is a usage error.
    assert code == 2
    # With the DB simply absent, the verdict is SKIPPED, not an error.
    verdict = session_end.run_hook(
        session_id="s1",
        sessions_db=tmp_path / "missing.db",
        data_dir=tmp_path / "data",
        environ={},
    )
    assert verdict["publication_status"] == "SKIPPED"
    assert "not a file" in verdict["reason"]
    # And with neither a session id nor a store, resolution itself fails.
    verdict = session_end.run_hook(
        sessions_db=tmp_path / "missing.db",
        data_dir=tmp_path / "data2",
        environ={},
    )
    assert verdict["publication_status"] == "SKIPPED"
    assert "could not resolve" in verdict["reason"]


def test_unresolvable_session_writes_unresolved(tmp_path, monkeypatch):
    # No flag, empty stdin, no env, no db → SKIPPED to _unresolved.json.
    data = tmp_path / "data"
    verdict = session_end.run_hook(
        sessions_db=tmp_path / "missing.db",
        data_dir=data,
        environ={},
    )
    assert verdict["publication_status"] == "SKIPPED"
    assert verdict["session_id"] is None
    assert (data / "redact" / "_unresolved.json").is_file()


def test_corrupt_db_is_skipped_not_raised(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"not a sqlite database at all")
    verdict = session_end.run_hook(
        session_id="s1",
        sessions_db=bad,
        data_dir=tmp_path / "data",
        environ={},
    )
    assert verdict["publication_status"] == "SKIPPED"


# --- side-file guarantees -----------------------------------------------------


def test_side_file_never_touches_the_store(tmp_path, monkeypatch):
    db = _db(tmp_path)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    _run(
        ["session-end", "--session-id", DIRTY_SID, "--sessions-db", str(db),
         "--data-dir", str(tmp_path / "data")],
        monkeypatch,
    )
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    # Nothing written next to the store or inside it.
    assert [p.name for p in tmp_path.iterdir()] == ["sessions.db", "data"] or \
        not any(p.name.endswith(".json") for p in db.parent.iterdir())


def test_default_out_path_shape(tmp_path):
    out = session_end.default_out(tmp_path / "data", "sess-123")
    assert out == tmp_path / "data" / "redact" / "sess-123.json"


def test_json_flag_prints_verdict(tmp_path, monkeypatch, capsys):
    db = _db(tmp_path)
    code = _run(
        ["session-end", "--session-id", CLEAN_SID, "--sessions-db", str(db),
         "--data-dir", str(tmp_path / "data"), "--json"],
        monkeypatch,
    )
    assert code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["publication_status"] == "CLEAN"
    assert printed["hook"] == "session-end"


def test_scan_session_api(tmp_path):
    db = _db(tmp_path)
    report = devin_redact.engine.scan_session(db, DIRTY_SID)
    assert report["publication_status"] == "BLOCKED"
    assert report["session_id"] == DIRTY_SID
    fps = {f["fingerprint"] for f in report["findings"]}
    assert _fp(FAKE_API_KEY) in fps
    clean = devin_redact.engine.scan_session(db, CLEAN_SID)
    assert clean["publication_status"] == "CLEAN"
