# STATUS — devin-backup

Updated: 2026-09-29 · Milestone: **M1 (done)** · Version: 0.1.0

## Done in M1

- `src/devin_backup/stores.py` — discovers `**/*.db`, `**/*.vscdb` (skipping
  `-wal`/`-shm`/`-journal` sidecars) and `.devin/**` under a data dir;
  `default_data_dir()` / `default_backups_dir()` with `DEVIN_DATA_DIR` /
  `DEVIN_BACKUP_DIR` env overrides.
- `src/devin_backup/snapshot.py` — `create_snapshot()` →
  `<out>/<YYYYMMDDTHHMMSSZ>/` + `manifest.json`. SQLite files go through
  `Connection.backup()` (consistent while Devin runs) with `file-copy`
  fallback recorded in the manifest; per-file `size`/`sha256`/
  `schema_version` via `devin-internals-spec` (null for ledger-less stores).
- `src/devin_backup/verify.py` — sha256 + `PRAGMA integrity_check` per
  manifest entry; catches post-backup corruption *and* sources that were
  already corrupt at backup time; `skipped` integrity for non-SQLite files.
- `src/devin_backup/rotate.py` — `list_snapshots()` (newest first, kind
  `snapshot`/`pre-restore`/`unknown`) + `rotate_snapshots(keep)`; only
  timestamp-named manifest dirs are deletable.
- `src/devin_backup/restore.py` — dry-run by default; `--apply` writes;
  pre-restore backup (`pre-restore-<ts>/`, consistent copies + manifest) of
  every file it would overwrite; `backup=False` refuses to overwrite;
  manifest paths validated against traversal; schema-drift warnings
  ("backup is v15, current is v17").
- `src/devin_backup/cli.py` — thin argparse wrapper: `create`, `verify`
  (exit 1 on failure), `list`, `restore` (`--dry-run` default / `--apply`),
  `rotate` (requires `--yes`); exit 2 on errors.
- **48 tests, all green** (Windows, Python 3.11.9, pytest 9.1.1). Fixtures
  via `devin_internals.fixtures.create_devin_data_dir()` + synthetic
  `.devin/config.json`.
- `docs/SPEC.md` (EN canonical), shared README plus Windows/Linux platform
  guides, smoke-tested CLI end-to-end on a fixture dir (create → verify → dry-run/apply restore →
  pre-restore backup → rotate).

## Environment notes

- `python` = 3.11.9 w/ pytest 9.1.1; bare `pip` may resolve elsewhere —
  always `python -m pip`.
- `devin_internals` 0.2.0 installed site-wide (site-packages, not editable);
  local dev used `python -m pip install -e . --no-deps`.
- Windows console codepage mangles non-ASCII (`—` → ``) — keep CLI output
  ASCII.
- pip/git commands can exceed the default 30s exec timeout — use longer
  timeouts.

## Decisions / notes

- Manifest v1 keeps both per-file entries and a flat `schema_versions` map —
  restore compares it against live DBs to warn on drift.
- `pre-restore-*` dirs live next to snapshots (`<snapshot>/../`) and are
  exempt from rotation — they're safety nets, not backups.
- `.devin/` config is copied as plain files (not SQLite).
- Backup of a non-SQLite `*.db` falls back to file-copy; verify reports
  `integrity: skipped` for those.

## Remaining for M2 (per SPEC §10)

1. Scheduled backups — Windows Task Scheduler / cron integration.
2. Compression (`zip`/`.tar.zst`) and remote targets (S3/rclone).
3. PyPI publish (`pipx install devin-backup`) — name + account needed.
4. `verify --deep`: row-count diff between snapshot and live store.

## Blockers

None.
