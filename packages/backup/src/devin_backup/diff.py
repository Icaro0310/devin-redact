"""Compare a snapshot against the live Devin stores — read-only.

Answers "is this snapshot worth restoring?": for every file in the manifest
it reports whether the live copy is identical, changed, or missing, and it
lists live stores the snapshot never captured. Nothing is written; the exit
code is always 0 because this is a report, not a gate.

Caveat: ``sqlite3.Connection.backup()`` does not produce byte-identical
copies, so a sha256 mismatch alone does not mean a SQLite store changed.
For ``kind == "sqlite"`` entries the status is decided by a logical digest
(``iterdump``) while ``bytes_equal`` keeps the raw sha256 comparison.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from devin_backup.restore import _schema_warnings
from devin_backup.snapshot import (
    _connect_readonly,
    load_manifest,
    sha256_file,
)
from devin_backup.stores import (
    DataDirError,
    default_backups_dir,
    default_config_dir,
    discover_stores,
    is_sqlite_store,
)

SAME = "same"
DIFFERENT = "different"
SNAPSHOT_ONLY = "snapshot-only"
LIVE_ONLY = "live-only"
SNAPSHOT_MISSING = "snapshot-missing"


def _sqlite_digest(path: Path) -> str | None:
    """Content hash over the ``iterdump`` SQL stream; ``None`` if unreadable."""
    try:
        con = _connect_readonly(path)
        try:
            h = hashlib.sha256()
            for line in con.iterdump():
                h.update(line.encode("utf-8") + b"\n")
            return h.hexdigest()
        finally:
            con.close()
    except (OSError, sqlite3.Error):
        return None


def _table_counts(path: Path) -> dict[str, int]:
    con = _connect_readonly(path)
    try:
        names = [
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        return {
            t: con.execute(
                f'SELECT COUNT(*) FROM "{t.replace(chr(34), chr(34) * 2)}"'
            ).fetchone()[0]
            for t in names
        }
    finally:
        con.close()


def _live_only_file(store) -> dict:
    display = (
        f"config/{store.rel_path}"
        if store.root == "config"
        else store.rel_path
    )
    try:
        live_size = store.path.stat().st_size
    except OSError:
        live_size = None
    return {
        "path": display,
        "root": store.root,
        "kind": store.kind,
        "status": LIVE_ONLY,
        "snapshot_size": None,
        "snapshot_sha256": None,
        "live_size": live_size,
        "live_sha256": None,
        "bytes_equal": None,
        "content_equal": None,
        "tables": None,
        "size_delta": None,
    }


def _compare_file(
    entry: dict,
    snapshot_dir: Path,
    live_path: Path | None,
) -> dict:
    rel = entry["path"]
    root = entry.get("root", "data")
    display = f"config/{rel}" if root == "config" else rel
    snap_path = Path(entry.get("snapshot_path", rel))
    snap_file = snapshot_dir / snap_path
    kind = entry.get("kind") or (
        "sqlite" if is_sqlite_store(snap_path) else "file"
    )

    result = {
        "path": display,
        "root": root,
        "kind": kind,
        "snapshot_size": entry.get("size"),
        "snapshot_sha256": entry.get("sha256"),
        "live_size": None,
        "live_sha256": None,
        "bytes_equal": None,
        "content_equal": None,
        "tables": None,
        "size_delta": None,
    }

    if not snap_file.is_file():
        result["status"] = SNAPSHOT_MISSING
        return result
    if live_path is None or not live_path.is_file():
        result["status"] = SNAPSHOT_ONLY
        return result

    live_size = live_path.stat().st_size
    live_sha = sha256_file(live_path)
    result["live_size"] = live_size
    result["live_sha256"] = live_sha
    result["bytes_equal"] = live_sha == entry.get("sha256")
    if isinstance(entry.get("size"), int):
        result["size_delta"] = live_size - entry["size"]

    if kind == "sqlite":
        snap_digest = _sqlite_digest(snap_file)
        live_digest = _sqlite_digest(live_path)
        if snap_digest is not None and live_digest is not None:
            result["content_equal"] = snap_digest == live_digest
            if not result["content_equal"]:
                snap_tables = _table_counts(snap_file)
                live_tables = _table_counts(live_path)
                result["tables"] = {
                    t: [snap_tables.get(t), live_tables.get(t)]
                    for t in sorted(set(snap_tables) | set(live_tables))
                    if snap_tables.get(t) != live_tables.get(t)
                }
            result["status"] = (
                SAME if result["content_equal"] else DIFFERENT
            )
            return result

    result["status"] = SAME if result["bytes_equal"] else DIFFERENT
    return result


def diff_snapshot(
    snapshot_dir: str | Path,
    data_dir: str | Path,
    *,
    config_dir: str | Path | None = None,
) -> dict:
    """Diff a snapshot's manifest against the live data/config roots.

    Read-only — never writes to either side. Raises
    :class:`devin_backup.snapshot.SnapshotError` on an unreadable manifest and
    :class:`devin_backup.stores.DataDirError` when ``data_dir`` is missing.
    """
    snapshot_dir = Path(snapshot_dir).expanduser()
    data_dir = Path(data_dir).expanduser()
    manifest = load_manifest(snapshot_dir)

    covers_config = any(
        e.get("root", "data") == "config" for e in manifest["files"]
    )
    if config_dir is not None:
        config_dir = Path(config_dir).expanduser()
    elif covers_config:
        config_dir = default_config_dir()

    def live_path(entry: dict) -> Path | None:
        root = (
            config_dir if entry.get("root", "data") == "config" else data_dir
        )
        return root / entry["path"] if root is not None else None

    mapped = [(entry, live_path(entry)) for entry in manifest["files"]]
    files = [
        _compare_file(entry, snapshot_dir, live)
        for entry, live in mapped
    ]

    manifest_keys = {(e.get("root", "data"), e["path"]) for e in manifest["files"]}
    try:
        live_stores = discover_stores(
            data_dir,
            config_dir=config_dir if covers_config else None,
            exclude=[snapshot_dir.resolve(), default_backups_dir(data_dir)],
        )
    except DataDirError:
        live_stores = []
    extra = [
        _live_only_file(s)
        for s in live_stores
        if (s.root, s.rel_path) not in manifest_keys
    ]
    files.extend(extra)
    live_only = sorted(f["path"] for f in extra)

    counts = {
        SAME: 0,
        DIFFERENT: 0,
        SNAPSHOT_ONLY: 0,
        SNAPSHOT_MISSING: 0,
    }
    for f in files:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    counts[LIVE_ONLY] = len(live_only)
    drift = sum(
        counts[k] for k in (DIFFERENT, SNAPSHOT_ONLY, SNAPSHOT_MISSING, LIVE_ONLY)
    )
    return {
        "snapshot": str(snapshot_dir),
        "data_dir": str(data_dir),
        "config_dir": str(config_dir) if config_dir is not None else None,
        "created_at": manifest.get("created_at"),
        "identical": drift == 0,
        "summary": counts,
        "files": files,
        "live_only": live_only,
        "warnings": _schema_warnings(
            [(e, p) for e, p in mapped if p is not None]
        ),
    }
