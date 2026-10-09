import sys

import pytest
from devin_janitor.exporter import ExportError, run_export


def test_no_cmd_is_noop():
    run_export(None)  # must not raise
    run_export("")


def test_successful_command():
    run_export(f'"{sys.executable}" -c "pass"')


def test_failing_command_aborts():
    with pytest.raises(ExportError, match="exited"):
        run_export(f'"{sys.executable}" -c "import sys; sys.exit(2)"')


def test_missing_command_aborts(tmp_path):
    with pytest.raises(ExportError):
        run_export(
            f'"{sys.executable}" "{tmp_path}/does-not-exist.py"'
        )
