# devin-install-scheduler

Shared installer for the `devin-state` packages' daily jobs. Registers a
tagged `crontab` line on Linux/macOS, a `schtasks` entry on Windows, or a
job record in `<config-dir>/.devin-ecosystem/scheduled.json` (the F6
elapsed fallback ticked by devin-powerups' `UserPromptSubmit` hook).

Used by `devin-backup` (`devin-backup-daily`) and `devin-janitor`
(`devin-janitor-daily`). Not a Devin-facing CLI — library only.

```python
from devin_install_scheduler import install_daily

install_daily(
    job_name="my-job-daily",
    command=f'"{sys.executable}" -m my_pkg.cli run',
)
```

> Unofficial community project. Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.
