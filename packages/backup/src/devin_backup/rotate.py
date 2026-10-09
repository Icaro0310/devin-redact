"""Snapshot listing and rotation (keep last N).

Only directories whose name matches the snapshot timestamp pattern *and*
contain a ``manifest.json`` are ever deleted — ``pre-restore-*`` safety
backups and anything else in the directory are left alone.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from devin_backup.snapshot import (
    MANIFEST_NAME,
    PRE_RESTORE_PREFIX,
    SNAPSHOT_NAME_RE,
)


def _is_snapshot_dir(path: Path) -> bool:
    return (
        path.is_dir()
        and SNAPSHOT_NAME_RE.match(path.name) is not None
        and (path / MANIFEST_NAME).is_file()
    )


def _is_pre_restore_dir(path: Path) -> bool:
    return path.is_dir() and (
        path.name.startswith(PRE_RESTORE_PREFIX)
        or _manifest_kind(path) == "pre-restore"
    )


def _manifest_kind(path: Path) -> str | None:
    try:
        manifest = json.loads(
            (path / MANIFEST_NAME).read_text(encoding="utf-8")
        )
        return manifest.get("kind")
    except (OSError, json.JSONDecodeError):
        return None


def _read_manifest(path: Path) -> dict | None:
    try:
        manifest = json.loads(
            (path / MANIFEST_NAME).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return None
    return manifest if isinstance(manifest.get("files"), list) else None


def list_snapshots(backups_dir: str | Path) -> list[dict]:
    """All snapshot-like dirs in ``backups_dir``, newest first.

    Each entry: ``name``, ``path``, ``kind`` (``"snapshot"`` /
    ``"pre-restore"`` / ``"unknown"``), ``created_at``, ``files``, ``size``,
    ``schema_versions``.
    """
    backups_dir = Path(backups_dir).expanduser()
    if not backups_dir.is_dir():
        return []
    out = []
    for child in sorted(backups_dir.iterdir(), key=lambda p: p.name, reverse=True):
        if not child.is_dir():
            continue
        manifest = _read_manifest(child)
        if manifest is None:
            continue
        if _is_pre_restore_dir(child) or manifest.get("kind") == "pre-restore":
            kind = "pre-restore"
        elif SNAPSHOT_NAME_RE.match(child.name):
            kind = "snapshot"
        else:
            kind = "unknown"
        out.append(
            {
                "name": child.name,
                "path": str(child),
                "kind": kind,
                "created_at": manifest.get("created_at"),
                "files": len(manifest["files"]),
                "size": sum(f.get("size", 0) for f in manifest["files"]),
                "schema_versions": manifest.get("schema_versions", {}),
            }
        )
    return out


def rotate_snapshots(backups_dir: str | Path, keep: int) -> list[Path]:
    """Delete all but the ``keep`` newest snapshots. Returns deleted dirs.

    Only timestamp-named snapshot dirs are eligible; ``pre-restore-*``
    backups and unrecognized directories are always preserved.
    """
    if keep < 1:
        raise ValueError("keep must be >= 1")
    backups_dir = Path(backups_dir).expanduser()
    if not backups_dir.is_dir():
        return []

    regular = sorted(
        (d for d in backups_dir.iterdir() if _is_snapshot_dir(d)),
        key=lambda p: p.name,
    )
    doomed = regular[: max(0, len(regular) - keep)]
    for d in doomed:
        shutil.rmtree(d)
    return doomed
