"""Default locations for Devin's local session database.

Mirrors the candidate logic used across the ecosystem (same order as
``devin-history.paths``): ``%APPDATA%\\devin\\cli\\sessions.db`` on
Windows, ``~/Library/Application Support/devin/cli/sessions.db`` on
macOS, and on Linux ``$XDG_DATA_HOME/devin/cli/sessions.db`` (default
``~/.local/share``), then ``$XDG_CONFIG_HOME`` and ``~`` fallbacks.

Used by the ``sessionend-scan`` hook invocation so a SessionEnd handler
needs no arguments — it scans the store Devin actually uses.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIRNAME = "devin"
SESSIONS_DB_RELPATH = ("cli", "sessions.db")
# Optional override for the side-file data root (`--data-dir` on the CLI).
DATA_DIR_ENV = "DEVIN_REDACT_DATA_DIR"


def _roots(environ: dict[str, str], platform: str) -> list[Path]:
    if platform.startswith("win"):
        roots = []
        if environ.get("APPDATA"):
            roots.append(Path(environ["APPDATA"]))
        roots.append(Path.home() / "AppData" / "Roaming")
    elif platform == "darwin":
        roots = [Path.home() / "Library" / "Application Support"]
    else:
        roots = [
            Path(environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"),
            Path(environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"),
            Path.home(),
        ]
    return list(dict.fromkeys(roots))


def sessions_db_candidates(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> list[Path]:
    """Candidate paths for the CLI ``sessions.db``, newest layout first."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    return [
        root.joinpath(APP_DIRNAME, *SESSIONS_DB_RELPATH)
        for root in _roots(env, plat)
    ]


def default_sessions_db(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path | None:
    """First existing candidate, or ``None`` when no store is present."""
    for candidate in sessions_db_candidates(environ=environ, platform=platform):
        if candidate.is_file():
            return candidate
    return None


def data_dir_candidates(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> list[Path]:
    """Candidate Devin data roots — the dirs that contain ``cli/``."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    return [root / APP_DIRNAME for root in _roots(env, plat)]


def default_data_dir(
    environ: dict[str, str] | None = None,
    platform: str | None = None,
    sessions_db: Path | None = None,
) -> Path:
    """The Devin data root side files are derived from.

    ``DEVIN_REDACT_DATA_DIR`` wins; then the root of the resolved
    ``sessions.db`` when it sits in the standard
    ``<root>/devin/cli/sessions.db`` layout; else the first candidate
    root (``$XDG_DATA_HOME/devin`` or platform equivalent).
    """
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get(DATA_DIR_ENV)
    if override:
        return Path(override)
    db = Path(sessions_db) if sessions_db is not None else default_sessions_db(env, plat)
    if db is not None and db.parent.name == "cli" and db.parent.parent.name == APP_DIRNAME:
        return db.parent.parent
    return data_dir_candidates(env, plat)[0]


def default_redact_dir(
    environ: dict[str, str] | None = None,
    platform: str | None = None,
    sessions_db: Path | None = None,
) -> Path:
    """``<data-dir>/redact`` — where ``session-end`` verdict files live."""
    return (
        default_data_dir(
            environ=environ, platform=platform, sessions_db=sessions_db
        )
        / "redact"
    )
