import json
import sqlite3

import pytest

from devin_backup import snapshot, verify


def _manifest(snap):
    return json.loads((snap / "manifest.json").read_text(encoding="utf-8"))


def test_verify_fresh_snapshot_ok(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    report = verify.verify_snapshot(snap)
    assert report["ok"] is True
    assert report["failed"] == 0
    assert report["checked"] == len(report["results"]) == 5
    assert all(r["status"] == "ok" for r in report["results"])


def test_verify_uses_snapshot_paths_for_separate_config_root(
    data_dir, backups_dir, tmp_path
):
    config_root = tmp_path / "config" / "Devin"
    acp_db = config_root / "User" / "acp-messages" / "gui.db"
    acp_db.parent.mkdir(parents=True)
    with sqlite3.connect(acp_db) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")

    snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_root)
    report = verify.verify_snapshot(snap)

    assert report["ok"] is True
    assert any(r["path"] == "config/User/acp-messages/gui.db" for r in report["results"])


def test_verify_catches_corrupted_file(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    victim = next((snap / "User" / "acp-messages").glob("*.db"))
    with open(victim, "ab") as fh:
        fh.write(b"corrupted tail")

    report = verify.verify_snapshot(snap)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}[
        f"User/acp-messages/{victim.name}"
    ]
    assert result["status"] == "sha256-mismatch"
    assert result["checks"]["sha256"] is False
    assert result["checks"]["size"] is False


def test_verify_catches_missing_file(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    (snap / "User" / "globalStorage" / "state.vscdb").unlink()
    report = verify.verify_snapshot(snap)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}[
        "User/globalStorage/state.vscdb"
    ]
    assert result["status"] == "missing"
    assert result["checks"]["exists"] is False


def test_verify_detects_sqlite_integrity_failure(data_dir, backups_dir):
    """A file whose hash matches but whose DB is internally corrupt must fail.

    (Covers the case where the *source* was already corrupt at backup time.)
    """
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    db = snap / "cli" / "sessions.db"

    # break the schema text — integrity_check reports malformed schema
    con = sqlite3.connect(db)
    con.execute("PRAGMA writable_schema=ON")
    con.execute(
        "UPDATE sqlite_master SET sql='CREATE TABLE broken(' WHERE name='sessions'"
    )
    con.commit()
    con.close()

    # fix the manifest so size+sha256 pass and only integrity can catch it
    manifest_path = snap / "manifest.json"
    manifest = _manifest(snap)
    for entry in manifest["files"]:
        if entry["path"] == "cli/sessions.db":
            entry["size"] = db.stat().st_size
            entry["sha256"] = snapshot.sha256_file(db)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = verify.verify_snapshot(snap)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}["cli/sessions.db"]
    assert result["status"] == "integrity-failed"
    assert result["checks"]["sha256"] is True
    assert result["checks"]["integrity"].startswith("failed")


def test_verify_skips_integrity_for_plain_files(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    report = verify.verify_snapshot(snap)
    cfg = {r["path"]: r for r in report["results"]}[".devin/config.json"]
    assert cfg["checks"]["integrity"] == "skipped"


def test_verify_non_sqlite_db_content(data_dir, backups_dir, tmp_path):
    """A .db that is not really SQLite verifies by hash; integrity is skipped."""
    fake_dir = tmp_path / "fake"
    (fake_dir / "cli").mkdir(parents=True)
    (fake_dir / "cli" / "sessions.db").write_bytes(b"not sqlite at all")
    snap = snapshot.create_snapshot(fake_dir, backups_dir)
    report = verify.verify_snapshot(snap)
    assert report["ok"] is True
    result = report["results"][0]
    assert result["checks"]["integrity"] == "skipped"


def test_verify_missing_manifest_raises(tmp_path):
    empty = tmp_path / "not-a-snapshot"
    empty.mkdir()
    with pytest.raises(snapshot.SnapshotError):
        verify.verify_snapshot(empty)
