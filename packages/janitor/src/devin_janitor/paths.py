"""Locate Devin's local session stores across platforms.

The legacy script hardcoded a Windows path. This module detects separate
session-data and UI-config roots where the platform stores them separately:

- ``cli/sessions.db`` and ``cli/session_locks/`` under the data root
- ``User/acp-messages/`` under the UI-config root
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DevinPaths:
    """Resolved locations of Devin's local session stores."""

    root: Path
    sessions_db: Path
    acp_messages_dir: Path
    session_locks_dir: Path

    @classmethod
    def from_root(cls, root: str | Path) -> DevinPaths:
        root = Path(root).expanduser()
        return cls(
            root=root,
            sessions_db=root / "cli" / "sessions.db",
            acp_messages_dir=root / "User" / "acp-messages",
            session_locks_dir=root / "cli" / "session_locks",
        )


def default_data_root(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    """Best-guess Devin data dir for the current OS.

    ``DEVIN_DATA_DIR`` wins when set; otherwise per-platform convention:

    - Windows: ``%APPDATA%\\devin``
    - macOS:   ``~/Library/Application Support/devin``
    - Linux:   ``$XDG_DATA_HOME/devin`` (normally ``~/.local/share/devin``)
    """
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform

    override = env.get("DEVIN_DATA_DIR")
    if override:
        return Path(override).expanduser()

    if plat.startswith("win"):
        appdata = env.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / "devin"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "devin"
    data_home = Path(env.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    config_home = Path(env.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    candidates = [data_home / "devin", config_home / "devin", Path.home() / "devin"]
    return next(
        (root for root in candidates if (root / "cli" / "sessions.db").is_file()),
        candidates[0],
    )


def default_config_root(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get("DEVIN_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if plat.startswith("win"):
        appdata = env.get("APPDATA")
        return Path(appdata) / "Devin" if appdata else Path.home() / "AppData" / "Roaming" / "Devin"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "Devin"
    return Path(env.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "Devin"


def resolve(
    data_dir: str | Path | None = None,
    sessions_db: str | Path | None = None,
    acp_messages_dir: str | Path | None = None,
    session_locks_dir: str | Path | None = None,
    config_dir: str | Path | None = None,
    environ: dict[str, str] | None = None,
    platform: str | None = None,
) -> DevinPaths:
    """Resolve stores from explicit paths, then platform defaults."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    root = Path(data_dir).expanduser() if data_dir else default_data_root(env, plat)
    base = DevinPaths.from_root(root)
    if acp_messages_dir:
        acp_root = Path(acp_messages_dir).expanduser()
    elif config_dir:
        acp_root = Path(config_dir).expanduser() / "User" / "acp-messages"
    elif data_dir is None:
        acp_root = default_config_root(env, plat) / "User" / "acp-messages"
    else:
        acp_root = base.acp_messages_dir
    return DevinPaths(
        root=base.root,
        sessions_db=Path(sessions_db).expanduser()
        if sessions_db
        else base.sessions_db,
        acp_messages_dir=acp_root,
        session_locks_dir=Path(session_locks_dir).expanduser()
        if session_locks_dir
        else base.session_locks_dir,
    )
