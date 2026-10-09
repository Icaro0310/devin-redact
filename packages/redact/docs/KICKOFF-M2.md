# KICKOFF M2 — devin-redact

Continuation of M1 (see `STATUS.md` and `docs/SPEC.md` — read both first).
You are a dedicated session for THIS repository only. Same rules as M1:
all fixture secrets synthetic, SQLite `mode=ro` for scanning, small commits,
trailer `Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>`,
`git push` at the end, update `STATUS.md` + `CHANGELOG.md` when done.

## Goal

Turn the scanner into a real redactor: in-place SQLite redaction (safe),
the tool-call semantic layer, and the `verify` gate.

## Scope (in order)

1. **`redact()` real implementation** (`src/devin_redact/engine.py`):
   - In-place rewrite of matched cells: replace secret spans with
     `<REDACTED:sha256prefix>` (keep the JSON valid — redact leaf values,
     never corrupt structure).
   - SQLite writes ONLY on a copy or with explicit
     `--apply --i-know-this-is-irreversible`; mandatory `.bak` backup +
     single transaction + post-redact open test (rollback on failure).
   - Plain-text files: same masking, also gated behind `--apply`.
   - Dry-run stays default and prints exactly what would change.
2. **Semantic tool-call layer** (`src/devin_redact/semantic.py`):
   - Parse `tool_call_state.rawInput`; if the command reads a sensitive
     file (`cat .env`, `grep ... .env`, `type credentials.toml`, etc. —
     maintain a small sensitivity table), flag the associated
     `tool_call_update_json` output for redaction even when no pattern
     matches its content.
   - Findings get `kind="semantic-context"` so reports distinguish them.
3. **`verify` subcommand** (`cli.py`):
   - Runs `scan` and exits 0 when clean, 1 with
     `PUBLICATION STATUS: BLOCKED` + findings summary when not.
   - `--json` output option.
4. **Tests** — extend the corpus:
   - redact-on-copy produces masked DB that still opens + all planted
     secrets gone + fingerprints preserved in report;
   - transaction rollback on induced failure;
   - semantic layer catches the `cat .env` case where output has no
     pattern-shaped secret;
   - `verify` exit codes both ways.

## Explicitly OUT of M2 (M3 candidates)

- `devin-history` integration, PyPI publish, SessionEnd hook, `/redact`
  skill.

## Environment notes (from M1)

- `python` = 3.11 with pytest; use `python -m pip` (bare `pip` = Py3.14).
- Multi-line `python -c` produces no output — use script files.

## Done criteria

- `python -m pytest` — all tests green (M1's 12 + new).
- `verify` on the dirty fixture exits 1; on a redacted copy exits 0.
- `STATUS.md` → M2 done + what remains for M3.
