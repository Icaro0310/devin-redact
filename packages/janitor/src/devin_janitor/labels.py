"""JA-4: recognise automatic (automation-created) sessions via labels.

Sessions created by bridge/tooling carry ``origin:purpose`` labels.
``devin-bridge`` records them in a sidecar::

    <state-dir>/session-labels.json
    {"version": 1, "sessions": {"<sessionId>": {
        "label": "origin:purpose", "origin": "...", "purpose": "...",
        "createdAt": "<iso>", "cwd": "..."}}}

State dir resolution matches ``devin-bridge/src/labels.js``:

- ``DEVIN_BRIDGE_STATE_DIR`` wins when set
- Windows: ``%LOCALAPPDATA%\\devin-bridge``
- macOS:   ``~/Library/Application Support/devin-bridge``
- Linux:   ``$XDG_STATE_HOME/devin-bridge`` (``~/.local/state/devin-bridge``)

Sessions may also be labelled by hooks_dispatch-registered handlers — they
write into the same sidecar, so a single read covers every producer.
Reading is advisory only: a missing or corrupt sidecar yields ``{}``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from devin_janitor.inventory import SessionRow

LABELS_FILENAME = "session-labels.json"

# Label origins that mark a session as automation-created rather than human
# work. ``bridge`` is the devin-bridge origin; the set exists so other
# tooling writing the same sidecar format can be recognised too.
AUTOMATIC_ORIGINS = frozenset({"bridge"})


def bridge_state_dir(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    """devin-bridge state dir — mirrors ``bridgeStateDir()`` in labels.js."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get("DEVIN_BRIDGE_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if plat.startswith("win"):
        local = env.get("LOCALAPPDATA") or str(
            Path.home() / "AppData" / "Local"
        )
        return Path(local) / "devin-bridge"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "devin-bridge"
    state_home = env.get("XDG_STATE_HOME") or str(
        Path.home() / ".local" / "state"
    )
    return Path(state_home) / "devin-bridge"


def default_labels_path(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    return bridge_state_dir(environ, platform) / LABELS_FILENAME


def load_labels(path: str | Path | None = None) -> dict[str, dict]:
    """``session_id -> {label, origin, purpose, createdAt, cwd}``.

    Fail-open: missing file, corrupt JSON or an unexpected shape all
    produce an empty mapping — detection is advisory, never fatal.
    """
    p = (
        Path(path).expanduser()
        if path is not None
        else default_labels_path()
    )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    sessions = data.get("sessions") if isinstance(data, dict) else None
    if not isinstance(sessions, dict):
        return {}
    out: dict[str, dict] = {}
    for sid, entry in sessions.items():
        if not isinstance(entry, dict):
            continue
        origin = entry.get("origin")
        purpose = entry.get("purpose")
        label = entry.get("label")
        if not label and (origin or purpose):
            label = f"{origin or '?'}:{purpose or 'unlabeled'}"
        out[str(sid)] = {
            "label": str(label) if label else "",
            "origin": str(origin) if origin else "",
            "purpose": str(purpose) if purpose else "",
            "createdAt": entry.get("createdAt"),
            "cwd": entry.get("cwd"),
        }
    return out


def automatic_sessions(
    rows: list[SessionRow],
    labels: dict[str, dict],
    origins: set[str] | frozenset[str] | None = None,
) -> list[dict]:
    """Inventory rows whose sidecar label marks them as automation.

    ``origins`` defaults to :data:`AUTOMATIC_ORIGINS`. Each result carries
    the sidecar entry plus the session's own fields for reporting.
    """
    wanted = AUTOMATIC_ORIGINS if origins is None else set(origins)
    out: list[dict] = []
    for r in rows:
        entry = labels.get(r.id)
        if not entry or entry.get("origin") not in wanted:
            continue
        out.append(
            {
                **entry,
                "id": r.id,
                "title": r.title,
                "session_origin": r.origin,
                "last_activity": r.last_activity,
            }
        )
    return out
