import json
import subprocess
from pathlib import Path

import pytest

from devin_install_scheduler import install as sched
from devin_install_scheduler import install_daily


def test_elapsed_writes_f6_registry(tmp_path):
    res = install_daily("devin-test-daily", '"py" -m pkg.cli run',
                        config_dir=str(tmp_path / "cfg"), backend="elapsed")
    assert res["backend"] == "elapsed"
    reg = json.loads(Path(res["registry"]).read_text())
    job = reg["jobs"]["devin-test-daily"]
    assert job["command"] == '"py" -m pkg.cli run'
    assert job["guarded_command"] == job["command"]
    assert job["interval_h"] == 24
    assert job["requires_devin_closed"] is False
    assert job["installed_at"] > 0 and job["last_run"] == 0


def test_bad_backend(tmp_path):
    with pytest.raises(ValueError):
        install_daily("j", "cmd", config_dir=str(tmp_path), backend="bogus")


def test_cron_tagged_line(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sched.shutil, "which", lambda _c: "/usr/bin/crontab")

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sched.subprocess, "run", fake_run)
    res = install_daily("devin-test-daily", '"py" -m pkg.cli run',
                        config_dir=str(tmp_path / "cfg"), backend="cron")
    assert res["backend"] == "cron"
    stdin = calls[-1][1]["input"]
    assert "@daily" in stdin
    assert "# devin-ecosystem:devin-test-daily" in stdin
