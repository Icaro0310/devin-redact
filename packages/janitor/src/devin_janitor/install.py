"""JA-1: install a scheduled ``devin-janitor report`` job.

Backends and registry format come from ``devin_install_scheduler`` (the
shared F6 scheduling foundation — cron, Task Scheduler, or the elapsed
config-registry fallback ticked by powerups' ``UserPromptSubmit`` hook).

The scheduled command is **report only** — ``python -m devin_janitor.cli
report`` using the current interpreter. It is read-only and advisory, so
the job does NOT require Devin closed. ``--apply`` is never scheduled:
deletion stays a manual, reviewed decision.
"""

from __future__ import annotations

import sys

from devin_install_scheduler import install_daily as _install_daily

JOB_NAME = "devin-janitor-daily"


def _report_command() -> str:
    """The scheduled command — read-only ``report``, never ``--apply``."""
    return f'"{sys.executable}" -m devin_janitor.cli report'


def install_daily(config_dir: str | None = None,
                  backend: str = "auto") -> dict:
    """Register the daily report job; returns what was done."""
    return _install_daily(JOB_NAME, _report_command(),
                          config_dir=config_dir, backend=backend)
