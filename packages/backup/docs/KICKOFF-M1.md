# KICKOFF M1 — devin-backup

You are the dedicated session for THIS repository. Scaffold from the
ecosystem template — fill with real content. Rules: `docs/SPEC.md` EN
canonical, bilingual READMEs, logic in `src/devin_backup/` + thin
`cli.py`, small commits + Devin trailer, `git push`, STATUS.md + CHANGELOG.md.

## One sentence

Safe backup & restore for Devin Desktop stores: timestamped snapshots of
`sessions.db`, `acp-messages/`, `state.vscdb` and `.devin/` config —
with SQLite-consistent copy, integrity verification and rotation.

## Devin-native differentiator

Knows which stores matter and uses `devin-internals-spec` schema
detection to record `schema_version` in each snapshot manifest — so a
restore can warn "this backup is v15, current is v17" instead of silently
downgrading your data.

Dependency:
```toml
"devin-internals-spec @ git+https://github.com/Icaro0310/devin-internals-spec.git@v0.2.0",
```

## Scope (M1)

`src/devin_backup/`:
- `snapshot.py` — copy stores via SQLite `VACUUM INTO` / backup API
  (consistent even while Devin runs; fall back to file copy when locked
  fails) → `backups/<timestamp>/` + `manifest.json` (files, sizes, sha256,
  schema versions).
- `verify.py` — re-check sha256 + `PRAGMA integrity_check` on restored DBs.
- `rotate.py` — keep last N snapshots (config), delete older safely.
- `restore.py` — restore a snapshot to a target dir with `--dry-run`
  default and pre-restore backup of current files.

## CLI

- `devin-backup create [--data-dir <path>] [--out <backups-dir>]`
- `devin-backup verify <snapshot-dir>`
- `devin-backup list [--out <backups-dir>]`
- `devin-backup restore <snapshot-dir> --to <data-dir> [--dry-run]`
- `devin-backup rotate [--keep N]` — destructive, requires `--yes`.

## Fixtures/tests

`devin_internals.fixtures` to fabricate a data dir. Tests: snapshot copies
all stores + manifest correct; verify catches a corrupted file; rotate
keeps N; restore dry-run writes nothing; restore refuses to overwrite
without backup; schema_version recorded in manifest.

## Env notes

`python`=3.11.9; `python -m pip` only; no multi-line `python -c`; Windows.
SQLite backup API: `sqlite3.Connection.backup()` — use it, not file copy,
for .db files when possible.

## Done

Tests green · CLI on fixture dir · docs real · pushed. M2 queue in
STATUS.md: scheduled/Task-Scheduler integration, compression, remote
target, PyPI.
