import json
from datetime import datetime, timedelta, timezone

import pytest

from devin_backup import rotate, snapshot

T0 = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _make_snapshots(data_dir, backups_dir, n):
    return [
        snapshot.create_snapshot(
            data_dir, backups_dir, now=T0 + timedelta(hours=i)
        )
        for i in range(n)
    ]


def test_rotate_keeps_newest_n(data_dir, backups_dir):
    snaps = _make_snapshots(data_dir, backups_dir, 4)
    deleted = rotate.rotate_snapshots(backups_dir, keep=2)
    assert sorted(p.name for p in deleted) == sorted(p.name for p in snaps[:2])
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])
    for d in snaps[2:]:
        assert (d / "manifest.json").is_file()


def test_rotate_noop_when_at_or_below_keep(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    assert rotate.rotate_snapshots(backups_dir, keep=5) == []
    assert len(list(backups_dir.iterdir())) == 2


def test_rotate_never_touches_pre_restore_backups(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    pre = backups_dir / "pre-restore-20990101T000000Z"
    pre.mkdir()
    (pre / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "kind": "pre-restore", "files": []}),
        encoding="utf-8",
    )
    rotate.rotate_snapshots(backups_dir, keep=1)
    assert pre.is_dir()
    assert len(list(backups_dir.iterdir())) == 2  # 1 kept snapshot + pre-restore


def test_rotate_never_touches_foreign_dirs(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    foreign = backups_dir / "some-other-tool"
    foreign.mkdir()
    rotate.rotate_snapshots(backups_dir, keep=1)
    assert foreign.is_dir()


def test_rotate_requires_keep_at_least_one(backups_dir):
    with pytest.raises(ValueError):
        rotate.rotate_snapshots(backups_dir, keep=0)


def test_rotate_missing_backups_dir(tmp_path):
    assert rotate.rotate_snapshots(tmp_path / "nope", keep=3) == []


def test_list_snapshots_sorted_newest_first(data_dir, backups_dir):
    snaps = _make_snapshots(data_dir, backups_dir, 3)
    listed = rotate.list_snapshots(backups_dir)
    assert [s["name"] for s in listed] == [s.name for s in reversed(snaps)]
    first = listed[0]
    assert first["files"] == 5
    assert first["size"] > 0
    assert first["kind"] == "snapshot"
    assert first["schema_versions"]["cli/sessions.db"] == 17


def test_list_snapshots_marks_pre_restore(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 1)
    pre = backups_dir / "pre-restore-20990101T000000Z"
    pre.mkdir()
    (pre / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "kind": "pre-restore", "files": []}),
        encoding="utf-8",
    )
    kinds = {s["name"]: s["kind"] for s in rotate.list_snapshots(backups_dir)}
    assert kinds["pre-restore-20990101T000000Z"] == "pre-restore"


def test_list_snapshots_empty(tmp_path):
    assert rotate.list_snapshots(tmp_path / "nope") == []
