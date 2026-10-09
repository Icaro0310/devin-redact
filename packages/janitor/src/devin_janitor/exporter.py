"""Optional export hook — the safety net run BEFORE any deletion.

``--export-cmd`` names a shell command (e.g. a devin-history export recipe)
that snapshots raw transcripts somewhere durable. If the command exits
non-zero the pipeline aborts: nothing is deleted without a fresh export.

Recommended pairing (see ``docs/SPEC.md``)::

    --export-cmd "python scripts/devin-history-export.py"
"""

from __future__ import annotations

import subprocess

EXPORT_TIMEOUT_S = 900


class ExportError(RuntimeError):
    """The export hook failed; the run must abort before deleting."""


def run_export(cmd: str | None, timeout: float = EXPORT_TIMEOUT_S) -> None:
    """Run the export hook. No-op when ``cmd`` is None/empty.

    Raises:
        ExportError: non-zero exit or the command could not run at all.
    """
    if not cmd:
        return
    try:
        rc = subprocess.run(cmd, shell=True, timeout=timeout, check=False).returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExportError(f"export command failed to run: {exc}") from exc
    if rc != 0:
        raise ExportError(f"export command exited {rc} — aborting before delete")
