import json
import sqlite3

import pytest

from devin_backup import cli, diff, snapshot


def _snap(data_dir, backups_dir):
    return snapshot.create_snapshot(data_dir, backups_dir)


def _by_path(report):
    return {f["path"]: f for f in report["files"]}


def test_diff_identical_snapshot_and_live(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    report = diff.diff_snapshot(snap, data_dir)

    assert report["identical"] is True
    assert report["live_only"] == []
    for f in report["files"]:
        assert f["status"] == diff.SAME
        assert f["size_delta"] == 0
    by = _by_path(report)
    # status for sqlite stores follows the logical content digest, not the
    # raw bytes (sqlite-backup copies are usually not byte-identical)
    sqlite = by["cli/sessions.db"]
    assert isinstance(sqlite["bytes_equal"], bool)
    assert sqlite["content_equal"] is True
    # plain file copies hash identically
    assert by[".devin/config.json"]["bytes_equal"] is True


def test_diff_changed_plain_file(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    cfg = data_dir / ".devin" / "config.json"
    # write_bytes: LF on every platform so size assertions don't depend on
    # Windows newline translation (\n -> \r\n)
    cfg.write_bytes(b'{"synthetic": false, "extra": 1}\n')

    report = diff.diff_snapshot(snap, data_dir)
    entry = _by_path(report)[".devin/config.json"]
    assert entry["status"] == diff.DIFFERENT
    assert entry["bytes_equal"] is False
    assert entry["size_delta"] == cfg.stat().st_size - 20
    assert report["identical"] is False


def test_diff_changed_sqlite_reports_table_counts(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    con = sqlite3.connect(data_dir / "cli" / "sessions.db")
    with con:
        con.execute(
            "INSERT INTO prompt_history(content, timestamp, session_id,"
            " is_shell) VALUES ('x', 1, 's', 0)"
        )
    con.close()

    report = diff.diff_snapshot(snap, data_dir)
    entry = _by_path(report)["cli/sessions.db"]
    assert entry["status"] == diff.DIFFERENT
    assert entry["content_equal"] is False
    assert entry["tables"]["prompt_history"] == [6, 7]


def test_diff_snapshot_only_and_live_only(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    next((data_dir / "User" / "acp-messages").glob("*.db")).unlink()
    (data_dir / ".devin" / "new.txt").write_text("new\n", encoding="utf-8")

    report = diff.diff_snapshot(snap, data_dir)
    by = _by_path(report)
    missing = [p for p, f in by.items() if f["status"] == diff.SNAPSHOT_ONLY]
    assert len(missing) == 1 and missing[0].startswith("User/acp-messages/")
    assert by[".devin/new.txt"]["status"] == diff.LIVE_ONLY
    assert report["live_only"] == [".devin/new.txt"]
    assert report["summary"]["live-only"] == 1


def test_diff_missing_file_in_snapshot(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    (snap / ".devin" / "config.json").unlink()

    report = diff.diff_snapshot(snap, data_dir)
    assert _by_path(report)[".devin/config.json"]["status"] == (
        diff.SNAPSHOT_MISSING
    )


def test_diff_missing_live_root_reports_all_snapshot_only(tmp_path):
    data_dir = tmp_path / "data"
    (data_dir / ".devin").mkdir(parents=True)
    (data_dir / ".devin" / "config.json").write_text("{}\n", encoding="utf-8")
    backups_dir = tmp_path / "backups"
    snap = snapshot.create_snapshot(data_dir, backups_dir)

    report = diff.diff_snapshot(snap, tmp_path / "gone")
    assert {f["status"] for f in report["files"]} == {diff.SNAPSHOT_ONLY}


def test_diff_config_root_entries(data_dir, backups_dir, tmp_path):
    config_root = tmp_path / "config" / "Devin"
    state = config_root / "User" / "globalStorage" / "state.vscdb"
    state.parent.mkdir(parents=True)
    with sqlite3.connect(state) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
    snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_root)

    report = diff.diff_snapshot(snap, data_dir, config_dir=config_root)
    entry = _by_path(report)["config/User/globalStorage/state.vscdb"]
    assert entry["status"] == diff.SAME
    assert entry["root"] == "config"


def test_diff_never_writes(data_dir, backups_dir):
    snap = _snap(data_dir, backups_dir)
    before = {
        p: p.stat().st_mtime_ns
        for root in (data_dir, snap)
        for p in root.rglob("*")
    }
    diff.diff_snapshot(snap, data_dir)
    after = {
        p: p.stat().st_mtime_ns
        for root in (data_dir, snap)
        for p in root.rglob("*")
    }
    assert before == after


def test_cli_diff_table_and_json(data_dir, backups_dir, capsys):
    snap = _snap(data_dir, backups_dir)
    (data_dir / ".devin" / "config.json").write_text(
        '{"changed": true}\n', encoding="utf-8"
    )
    assert cli.main(
        ["diff", str(snap), "--data-dir", str(data_dir)]
    ) == 0
    out = capsys.readouterr().out
    assert "different" in out and ".devin/config.json" in out
    assert "same" in out

    assert cli.main(
        ["diff", str(snap), "--data-dir", str(data_dir), "--json"]
    ) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["identical"] is False
    assert report["summary"]["different"] == 1


def test_cli_diff_exits_zero_even_with_differences(
    data_dir, backups_dir, capsys
):
    snap = _snap(data_dir, backups_dir)
    (data_dir / "cli" / "sessions.db").unlink()
    rc = cli.main(["diff", str(snap), "--data-dir", str(data_dir)])
    assert rc == 0
    assert "snapshot-only" in capsys.readouterr().out


def test_cli_diff_missing_manifest_errors(tmp_path, capsys):
    rc = cli.main(["diff", str(tmp_path), "--data-dir", str(tmp_path)])
    assert rc == 2
    assert "manifest" in capsys.readouterr().err
