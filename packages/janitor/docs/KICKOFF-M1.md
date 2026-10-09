# KICKOFF M1 — devin-janitor

Dedicated session for THIS repo. Template scaffold + `legacy/` contains the
proven original (`session-janitor.py`, its keep-file format and SKILL.md) —
**port it, don't call it**. Rules: `docs/SPEC.md` EN canonical, a shared README plus Windows/Linux
platform guides (problem/prior art/Devin extra/limitations/install), logic in
`src/devin_janitor/` + thin `cli.py`, small commits + Devin trailer, push,
STATUS.md + CHANGELOG.md.

## One sentence

The lifecycle janitor for Devin sessions: a safety-ordered pipeline —
**export first, classify in tiers, delete only the safe tiers, retry
locked files, vacuum only when Devin is closed** — so `sessions.db` and
`acp-messages/` never bloat with empty/automation noise again.

## Devin-native differentiator

Knows the real stores (sessions.db rows + GUI `acp-messages/*.db` files +
`session_locks/`) via `devin-internals-spec`, exports before deleting, and
has a **pluggable judge** for ambiguous sessions — classification by a
local LLM is opt-in, not required.

Dep: `"devin-internals-spec @ git+https://github.com/Icaro0310/devin-internals-spec.git@v0.2.0"`

## Port + generalize (the legacy script works — keep its semantics)

`legacy/session-janitor.py` hardcodes user paths. Turn into config-driven:

- `paths.py` — auto-detect `%APPDATA%/devin` (Win/macOS/Linux), sessions.db,
  acp-messages dir, session_locks.
- `tiers.py` — classifier returning KEEP / AUTO_DELETE / JUDGE per session:
  - KEEP: keep-file ids/title_patterns, "não apagar", grace window
    (`--grace-hours`, default 48h)
  - AUTO_DELETE: empty sessions, NOISE_RE automation patterns,
    EPHEMERAL_RE cycles, duplicates (keep sibling w/ most activity)
  - JUDGE: weak/ambiguous signals only
- `judge.py` — **pluggable backend**: `--judge none|command:<cmd>`.
  `none` = default → all JUDGE sessions kept (fail-open, same as legacy).
  `command` pipes the statement+summary to any CLI judge (e.g. a
  poordjaevin/Devin-ACP helper). Judge unreachable ⇒ keep.
- `exporter.py` — optional `--export-cmd` hook run BEFORE any deletion
  (default off; document the devin-history-export recipe). Abort pipeline
  if it fails.
- `execute.py` — delete session rows (all MSG_TABLES + sessions row) +
  acp-messages files; locked/failed deletions → `janitor-pending.json`
  retry queue; VACUUM only when no lock/devin.exe absent.
- `report.py` — per-run audit log JSONL (`janitor-log.jsonl`: id, reason,
  tier, judge verdict) + human summary.

## CLI (dry-run is ALWAYS default)

- `devin-janitor scan [--sessions-db] [--json]` — classification preview.
- `devin-janitor run [--apply] [--grace-hours N] [--judge none|command:<cmd>]
  [--export-cmd "..."] [--keep-file <path>] [--pending-file <path>]`
- `devin-janitor pending [--retry|--list]`
- `run` without `--apply` prints the exact plan and exits 0.

## Fixtures/tests (fixtures-first TDD)

`devin_internals.fixtures` for sessions.db + fabricated acp files + lock
files. Tests cover: each tier's rules, grace window, keep-file matching,
duplicate resolution, judge fail-open (backend down ⇒ kept), pending
retry, export-failure aborts run, VACUUM skip when locked, audit log
shape, dry-run writes NOTHING (hash-compare db + file list).

## Env notes

`python`=3.11.9; `python -m pip` only; cmd.exe — no heredocs/multi-line
`python -c`; use multiple `-m` commit flags.

## Done

Tests green · `run` dry-run + `--apply` verified on fixture dir · docs
real (incl. "default judge=none is purely rules-based" limitation) ·
pushed. M2 queue in STATUS.md: Task Scheduler `install` subcommand,
devin-history dependency instead of export-cmd, Slack digest, PyPI.
