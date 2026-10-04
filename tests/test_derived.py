"""RD-5: scan coverage of derived stores.

``sessions.db`` is not the only SQLite file that inherits session
sensitivity — devin-graph's ``graph.db``, devin-search's ``search.db``,
devin-memory's ``memory.db``, the GUI ``acp-messages/*.db`` stores and
exported markdown/json notes all carry transcript text. The target
dispatcher detects SQLite by extension *or* by the ``SQLite format 3``
magic header, and scans every text column read-only.
"""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import devin_redact
from devin_redact.engine import _target_type

from test_scan import FAKE_API_KEY, FAKE_GITHUB_TOKEN, _fp


def _make_db(path: Path, rows: list[str], *, fts5: bool = False) -> Path:
    con = sqlite3.connect(path)
    with con:
        if fts5:
            con.execute(
                "CREATE VIRTUAL TABLE docs USING fts5(text, session_id UNINDEXED)"
            )
            con.executemany(
                "INSERT INTO docs(text, session_id) VALUES (?, ?)",
                [(r, "sess-fake") for r in rows],
            )
        else:
            con.execute("CREATE TABLE entries(id INTEGER PRIMARY KEY, body TEXT)")
            con.executemany(
                "INSERT INTO entries(body) VALUES (?)", [(r,) for r in rows]
            )
    con.close()
    return path


def test_derived_dbs_are_scanned(tmp_path):
    targets = [
        _make_db(tmp_path / "graph.db", ["edge note leaked " + FAKE_API_KEY]),
        _make_db(tmp_path / "search.db", ["doc text " + FAKE_GITHUB_TOKEN], fts5=True),
        _make_db(tmp_path / "memory.db", ["remember token " + FAKE_API_KEY]),
    ]
    report = devin_redact.scan(targets)
    assert report["publication_status"] == "BLOCKED"
    assert report["files_scanned"] == 3
    files = {str(f["file"]) for f in report["findings"]}
    for t in targets:
        assert str(t) in files, f"no findings in {t}"
    locations = [str(f["location"]) for f in report["findings"]]
    assert any("entries.body#rowid=" in loc for loc in locations)
    # FTS5 store: the virtual table's text column is scanned too.
    assert any("docs.text#rowid=" in loc for loc in locations)


def test_sqlite_detected_by_magic_not_extension(tmp_path):
    # A derived store with no .db suffix still scans as a database.
    weird = _make_db(tmp_path / "session-cache", ["key " + FAKE_API_KEY])
    assert _target_type(weird) == "sqlite"
    report = devin_redact.scan([weird])
    assert report["findings_total"] >= 1
    assert any(
        "#rowid=" in str(f["location"]) for f in report["findings"]
    )


def test_non_sqlite_binary_still_skipped(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x89PNG\x00\x01binary" + bytes(range(256)))
    assert _target_type(blob) == "binary"
    report = devin_redact.scan([blob])
    assert report["findings_total"] == 0
    assert report["errors"] and "binary" in report["errors"][0]["error"]


def test_target_type_classification(tmp_path):
    db = _make_db(tmp_path / "x.dat", ["clean"])
    md = tmp_path / "note.md"
    md.write_text("plain text\n", encoding="utf-8")
    assert _target_type(db) == "sqlite"
    assert _target_type(md) == "text"
    assert _target_type(tmp_path / "missing") == "binary"


def test_exported_notes_dir_scanned(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-05-28_sess-fake.md").write_text(
        "# session\nused key " + FAKE_API_KEY + "\n", encoding="utf-8"
    )
    (notes / "index.json").write_text(
        '{"note": "token ' + FAKE_GITHUB_TOKEN + '"}', encoding="utf-8"
    )
    report = devin_redact.scan([notes])
    assert report["publication_status"] == "BLOCKED"
    files = {Path(str(f["file"])).name for f in report["findings"]}
    assert "2026-05-28_sess-fake.md" in files
    assert "index.json" in files


def test_scan_derived_is_read_only(tmp_path):
    db = _make_db(tmp_path / "graph.db", ["k " + FAKE_API_KEY])
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    devin_redact.scan([db])
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_redact_derived_db_apply(tmp_path):
    db = _make_db(tmp_path / "memory.db", ["secret " + FAKE_API_KEY])
    src = tmp_path / "copy" / "memory.db"
    src.parent.mkdir()
    shutil.copy2(db, src)
    result = devin_redact.redact([src], apply=True, confirm_irreversible=True)
    assert result["applied_ok"] is True
    assert src.with_name("memory.db.bak").exists()
    con = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    (body,) = con.execute("SELECT body FROM entries").fetchone()
    con.close()
    assert "<REDACTED:" in body
    assert FAKE_API_KEY not in body
    clean = devin_redact.scan([src])
    assert _fp(FAKE_API_KEY) not in {
        str(f["fingerprint"]) for f in clean["findings"]
    }
