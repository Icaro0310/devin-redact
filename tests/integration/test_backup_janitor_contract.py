"""Contract test: the manifest devin-janitor's tier-3 guard consumes.

`devin-janitor cleanup --tier3` refuses to delete GUI state unless a
verified devin-backup snapshot manifest younger than 24h covers
`state.vscdb`. It re-implements the manifest format on its side
(`manifest_version in {1,2}`, `files[]` entries with `path`, `size`,
`sha256`, optional `snapshot_path`, ISO-8601 `created_at`).

These tests pin the producer side of that contract so a manifest change
that would break janitor fails here first. The consumer-side rules are
documented in `docs/snapshot-contract.md`.
"""

import json
import sqlite3
import time
from datetime import datetime

from devin_backup import snapshot

# Fields devin-janitor/cleanup.py::verify_snapshot requires.
REQUIRED_MANIFEST_FIELDS = {"manifest_version", "created_at", "files"}
REQUIRED_FILE_FIELDS = {"path"}  # size/sha256 enforced when present
SUPPORTED_MANIFEST_VERSIONS = {1, 2}
TIER3_REQUIRED_FILENAME = "state.vscdb"
TIER3_MAX_AGE_S = 24 * 3600


def test_manifest_shape_satisfies_janitor(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text())

    assert REQUIRED_MANIFEST_FIELDS <= set(manifest)
    assert manifest["manifest_version"] in SUPPORTED_MANIFEST_VERSIONS
    assert isinstance(manifest["files"], list)

    for entry in manifest["files"]:
        assert REQUIRED_FILE_FIELDS <= set(entry)
        f = snap / (entry.get("snapshot_path") or entry["path"])
        assert f.is_file(), entry["path"]
        if "size" in entry:
            assert f.stat().st_size == entry["size"]
        if "sha256" in entry:
            import hashlib

            assert hashlib.sha256(f.read_bytes()).hexdigest() == entry["sha256"]


def test_created_at_is_fresh_and_timezone_aware(data_dir, backups_dir):
    """Janitor rejects manifests it cannot parse or older than 24h."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text())
    created = datetime.fromisoformat(manifest["created_at"])
    assert created.tzinfo is not None, "created_at must carry a timezone"
    assert created.utcoffset().total_seconds() == 0, "created_at must be UTC"
    age = time.time() - created.timestamp()
    assert 0 <= age < TIER3_MAX_AGE_S


def test_manifest_covers_state_vscdb(data_dir, backups_dir):
    """Tier-3 needs a manifest whose files cover `state.vscdb` exactly —
    a `state.vscdb.old` entry must not satisfy coverage."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text())
    covering = [
        e
        for e in manifest["files"]
        if str(e.get("path", "")).replace("\\", "/").endswith(
            "/" + TIER3_REQUIRED_FILENAME
        )
        or e.get("path") == TIER3_REQUIRED_FILENAME
    ]
    assert covering, (
        "manifest lost state.vscdb coverage — janitor tier-3 would refuse"
    )
    # the covering entry is the real file, not a lookalike name
    assert all(
        str(e["path"]).replace("\\", "/").rsplit("/", 1)[-1]
        == TIER3_REQUIRED_FILENAME
        for e in covering
    )


def test_config_root_state_vscdb_reachable_via_snapshot_path(
    data_dir, backups_dir, tmp_path
):
    """On Linux the UI store lives in a separate config root; janitor
    resolves files via `snapshot_path`, so the entry must point at the
    copied file inside the snapshot."""
    config_root = tmp_path / "config" / "Devin"
    state_db = config_root / "User" / "globalStorage" / "state.vscdb"
    state_db.parent.mkdir(parents=True)
    with sqlite3.connect(state_db) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")

    snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_root)
    manifest = json.loads((snap / "manifest.json").read_text())

    # The data fixture ships its own state.vscdb (root="data"), so match
    # the config-root entry explicitly — picking the first endswith match
    # would pass even if config copying regressed.
    entry = next(
        (
            e
            for e in manifest["files"]
            if e.get("root") == "config"
            and str(e.get("path", "")).replace("\\", "/").endswith(
                "/" + TIER3_REQUIRED_FILENAME
            )
        ),
        None,
    )
    assert entry is not None, "config-root state.vscdb missing from manifest"
    target = snap / (entry.get("snapshot_path") or entry["path"])
    assert target.is_file(), (
        f"janitor resolves {entry.get('snapshot_path') or entry['path']!r} "
        "relative to the snapshot dir"
    )
    # Content proves the *config* file was copied, not the data-root one.
    with sqlite3.connect(target) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "sample" in tables
