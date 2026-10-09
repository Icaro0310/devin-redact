"""Install a daily scheduled job for a devin-state package.

The F6 scheduling foundation — the same backends and registry format as
``devin-powerups/tools/schedule.py``:

- **cron** (Linux/macOS): a tagged ``crontab`` line.
- **tasksch** (Windows): a daily ``schtasks`` entry.
- **elapsed** (corporate fallback): a job record in
  ``<config-dir>/.devin-ecosystem/scheduled.json`` that the F6
  ``UserPromptSubmit`` hook ticks — see powerups' schedule.py.

Callers supply the job name and the command to schedule; this module owns
backend selection and the registry write.
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


def _install_cron(command: str, cron_tag: str) -> bool:
    """Append the tagged daily line to crontab. Returns False if no cron."""
    # shutil.which IS the capability check: no crontab.exe exists on a
    # vanilla Windows PATH, so an explicit sys.platform guard adds nothing
    # and makes the line-building logic untestable there.
    if not shutil.which("crontab"):
        return False
    out = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = out.stdout if out.returncode == 0 else ""
    kept = [l for l in current.splitlines() if cron_tag not in l]
    kept.append(f"@daily {command}  {cron_tag}")
    subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n",
                   text=True, check=True)
    return True


def _install_tasksch(command: str, job_name: str) -> bool:
    if not sys.platform.startswith("win") or not shutil.which("schtasks"):
        return False
    subprocess.run(
        ["schtasks", "/create", "/f", "/tn", job_name,
         "/sc", "DAILY", "/tr", command], check=True)
    return True


def install_daily(job_name: str,
                  command: str,
                  config_dir: str | None = None,
                  backend: str = "auto") -> dict:
    """Register a daily job; returns what was done."""
    cron_tag = f"# devin-ecosystem:{job_name}"
    cfg = _config_dir(config_dir)
    used = backend
    if backend == "auto":
        if _install_tasksch(command, job_name):
            used = "tasksch"
        elif _install_cron(command, cron_tag):
            used = "cron"
        else:
            used = "elapsed"
    elif backend == "tasksch":
        _install_tasksch(command, job_name)
    elif backend == "cron":
        if not _install_cron(command, cron_tag):
            raise RuntimeError("cron backend requested but `crontab` "
                               "is not available")
    elif backend != "elapsed":
        raise ValueError(f"unknown backend {backend!r}")

    reg = _load_registry(cfg)
    reg["jobs"][job_name] = {
        "command": command,
        "guarded_command": command,
        "interval_h": 24,
        "backend": used,
        "requires_devin_closed": False,
        "installed_at": int(time.time()),
        "last_run": 0,
    }
    _save_registry(cfg, reg)
    return {"job": job_name, "backend": used, "command": command,
            "registry": str(_registry_path(cfg))}
