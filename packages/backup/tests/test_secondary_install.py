"""BK-1 install + BK-2 copy-to."""

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devin_backup import install, secondary, snapshot


def _mk_snapshot(tmp_path):
    data = tmp_path / "data"
    (data / "cli").mkdir(parents=True)
    con = sqlite3.connect(data / "cli" / "sessions.db")
    con.executescript("""
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    INSERT INTO meta VALUES ('schema_version','17');
    CREATE TABLE sessions(id TEXT PRIMARY KEY);
    """)
    con.commit(); con.close()
    out = tmp_path / "snaps"
    return snapshot.create_snapshot(data, out)


def test_copy_to_verifies_dest(tmp_path):
    snap = _mk_snapshot(tmp_path)
    dest = tmp_path / "nas"
    dest.mkdir()
    res = secondary.copy_to(snap, dest)
    assert res["verify"]["ok"] and res["verify"]["checked"] >= 1
    assert (Path(res["dest"]) / "manifest.json").is_file()


def test_copy_to_corrupt_copy_fails(tmp_path, monkeypatch):
    snap = _mk_snapshot(tmp_path)
    dest = tmp_path / "nas"; dest.mkdir()
    real_copytree = secondary.shutil.copytree

    def bad_copy(s, d, *a, **kw):
        real_copytree(s, d, *a, **kw)
        for f in Path(d).rglob("*.db"):
            f.write_bytes(b"corrupt")

    monkeypatch.setattr(secondary.shutil, "copytree", bad_copy)
    with pytest.raises(snapshot.SnapshotError, match="re-verification"):
        secondary.copy_to(snap, dest)
    assert not list(dest.iterdir())  # partial copy removed


def test_copy_to_existing_dest_refused(tmp_path):
    snap = _mk_snapshot(tmp_path)
    dest = tmp_path / "nas"; (dest / snap.name).mkdir(parents=True)
    with pytest.raises(snapshot.SnapshotError, match="already exists"):
        secondary.copy_to(snap, dest)


def test_install_elapsed_writes_f6_registry(tmp_path):
    res = install.install_daily(out_dir="/tmp/snaps",
                                config_dir=str(tmp_path / "cfg"),
                                backend="elapsed")
    assert res["backend"] == "elapsed"
    reg = json.loads(Path(res["registry"]).read_text())
    job = reg["jobs"]["devin-backup-daily"]
    assert "devin_backup.cli create" in job["command"]
    assert "--out \"/tmp/snaps\"" in job["command"]
    assert job["interval_h"] == 24
    assert job["requires_devin_closed"] is False


def test_install_bad_backend(tmp_path):
    with pytest.raises(ValueError):
        install.install_daily(config_dir=str(tmp_path), backend="bogus")
