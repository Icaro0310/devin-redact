"""BK-1: install a scheduled ``devin-backup create`` job.

Built on the F6 scheduling foundation — the same backends and registry
format as ``devin-powerups/tools/schedule.py``:

- **cron** (Linux/macOS): a tagged ``crontab`` line.
- **tasksch** (Windows): a daily ``schtasks`` entry.
- **elapsed** (corporate fallback): a job record in
  ``<config-dir>/.devin-ecosystem/scheduled.json`` that the F6
  ``UserPromptSubmit`` hook ticks — see powerups' schedule.py.

Backups write files but never touch Devin's stores destructively, so the
job does NOT require Devin closed — it only needs Devin's stores readable
(sqlite backup API tolerates a live store).

The scheduled command is ``python -m devin_backup.cli create --out DIR``
using the current interpreter, so it works from a venv install.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

JOB_NAME = "devin-backup-daily"
CRON_TAG = f"# devin-ecosystem:{JOB_NAME}"


def _config_dir(override: str | None) -> Path:
    if override:
        return Path(override).expanduser()
    env = os.environ.get("DEVIN_CONFIG_DIR")
    if env:
        return Path(env).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(
            Path.home() / "AppData" / "Roaming")
        return Path(base) / "Devin"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Devin"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    for name in ("Devin", "devin"):
        if (Path(xdg) / name).is_dir():
            return Path(xdg) / name
    return Path(xdg) / "devin"


def _registry_path(config_dir: Path) -> Path:
    return config_dir / ".devin-ecosystem" / "scheduled.json"


def _load_registry(config_dir: Path) -> dict:
    try:
        data = json.loads(_registry_path(config_dir).read_text(
            encoding="utf-8"))
        if isinstance(data.get("jobs"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "jobs": {}}


def _save_registry(config_dir: Path, reg: dict) -> None:
    p = _registry_path(config_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2)
    os.replace(tmp, p)


def _create_command(out_dir: str | None) -> str:
    cmd = f'"{sys.executable}" -m devin_backup.cli create'
    if out_dir:
        cmd += f' --out "{out_dir}"'
    return cmd


def _install_cron(command: str) -> bool:
    """Append the tagged daily line to crontab. Returns False if no cron."""
    if sys.platform.startswith("win") or not shutil.which("crontab"):
        return False
    out = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = out.stdout if out.returncode == 0 else ""
    kept = [l for l in current.splitlines() if CRON_TAG not in l]
    kept.append(f"@daily {command}  {CRON_TAG}")
    subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n",
                   text=True, check=True)
    return True


def _install_tasksch(command: str) -> bool:
    if not sys.platform.startswith("win") or not shutil.which("schtasks"):
        return False
    subprocess.run(
        ["schtasks", "/create", "/f", "/tn", "devin-backup-daily",
         "/sc", "DAILY", "/tr", command], check=True)
    return True


def install_daily(out_dir: str | None = None,
                  config_dir: str | None = None,
                  backend: str = "auto") -> dict:
    """Register the daily backup job; returns what was done."""
    cfg = _config_dir(config_dir)
    command = _create_command(out_dir)
    used = backend
    if backend == "auto":
        if _install_tasksch(command):
            used = "tasksch"
        elif _install_cron(command):
            used = "cron"
        else:
            used = "elapsed"
    elif backend == "tasksch":
        _install_tasksch(command)
    elif backend == "cron":
        if not _install_cron(command):
            raise RuntimeError("cron backend requested but `crontab` "
                               "is not available")
    elif backend != "elapsed":
        raise ValueError(f"unknown backend {backend!r}")

    reg = _load_registry(cfg)
    reg["jobs"][JOB_NAME] = {
        "command": command,
        "guarded_command": command,
        "interval_h": 24,
        "backend": used,
        "requires_devin_closed": False,
        "installed_at": int(time.time()),
        "last_run": 0,
    }
    _save_registry(cfg, reg)
    return {"job": JOB_NAME, "backend": used, "command": command,
            "registry": str(_registry_path(cfg))}
