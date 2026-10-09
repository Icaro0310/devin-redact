# Kickoff M1 — devin-redact

You are a dedicated Devin session for the repository **devin-redact**
(your working directory IS the repo root). You work autonomously; the human
orchestrator reviews your git history and STATUS.md afterwards.

## Context

- This repo belongs to the `devin-*` powerups ecosystem (hub: `Icaro0310/devin-powerups`).
- Public docs use one shared English `README.md` plus `README.windows.md` and
  `README.linux.md` for OS-specific setup. License: MIT; all guides carry the
  unofficial notice.
- Architecture rule: logic lives in `src/devin_redact/` (the library);
  the CLI is a thin wrapper.
- TDD: **fixture corpus before the engine**. Deterministic fixtures.
- Tests must pass on Windows and Linux.

## Authoritative spec

`docs/SPEC.pt-BR.md` (Portuguese). Your first deliverable includes the
canonical English translation at `docs/SPEC.md`.

## Evidence you may use

The shape of the real store (schema ONLY, read-only, never copy row content):

- `%APPDATA%\devin\cli\sessions.db` — tables:
  `sessions`, `message_nodes` (`chat_message`, `metadata` JSON),
  `tool_call_state` (`tool_call_json` with `rawInput`/`locations`,
  `tool_call_update_json` with `status`), `app_state`,
  `refinery_schema_history`

Python 3.11: ``py -3.11` (or `python` on PATH)`.
This is Windows; mind console encoding.

## Milestone M1 scope (do exactly this, no more)

1. `docs/SPEC.md` — canonical EN translation of the spec.
2. Keep shared purpose and usage in `README.md`; put Windows- and Linux-specific
   install/path instructions in their respective guides. Include prior art,
   the Devin-native extra, limitations, and the false-negative disclaimer.
3. `tests/fixtures/` — corpus with **planted synthetic secrets**: a
   `sessions.db` fixture (tool call whose `rawInput` is `cat .env` and whose
   output contains secrets), a `memories.jsonl`, a Markdown export, a `.env`.
   All secrets must be obviously fake (e.g. `sk-FAKE...`, `PASSWORD=hunter2fake`).
4. `src/devin_redact/patterns.py` — detection patterns: API keys, bearer
   tokens, GitHub tokens (`ghp_`, `gho_`), private keys, `.env` assignments,
   Devin pairing codes, emails, absolute user paths.
5. `src/devin_redact/engine.py` — `scan()` returning the JSON report contract
   from the spec (files_scanned, counts by category, publication_status).
   `redact()` is stubbed for M2 — dry-run only.
6. `tests/` — scan finds all planted secrets (recall on corpus), benign text
   produces zero findings, idempotency.
7. Run `pytest` — all green.
8. Update `CHANGELOG.md` (0.1.0).
9. Write `STATUS.md` at repo root: what was done, what remains for M2
   (in-place SQLite redact, tool-call semantic layer, verify subcommand),
   blockers.
10. Commit in small logical commits with the trailer:
    `Generated with [Devin](https://devin.ai)` +
    `Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>`
    Then `git push` (origin is configured).

## Hard rules

- Stay inside the repo directory.
- NEVER run redaction against the real `sessions.db` — fixtures only.
- No telemetry, no real secrets (all fixture secrets are fake).
- If something blocks you, document it in STATUS.md and stop cleanly.
