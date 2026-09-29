# STATUS

## Milestone M1 — done (2026-09-29)

- `docs/SPEC.md` — canonical EN translation of `SPEC.pt-BR.md`.
- `README.md` + `README.pt-BR.md` — real content: problem (with the
  pairing-code evidence), prior art (geheim / agent-leaks / AgentLogs),
  the Devin-native differentiator (3 tests), usage, and a Limitations
  section that declares false negatives.
- `tests/fixtures/` — planted-secret corpus, all synthetic:
  - `sessions.db` — mirrors the real schema (`sessions`, `message_nodes`,
    `tool_call_state`, `prompt_history`, `app_state`,
    `refinery_schema_history`); contains a `cat .env` tool call whose
    `tool_call_update_json` output holds fake secrets, a chat message with
    a fake `sk-` key + email, and a pairing code in `prompt_history`.
    Regenerate with `python tests/fixtures/generate_sessions_db.py`
    (deterministic, committed alongside the DB).
  - `memories.jsonl`, `export.md`, `.env`, `benign.txt`.
  - `.gitignore` has explicit `!tests/fixtures/…` exceptions for `.env`
    and `*.db`.
- `src/devin_redact/patterns.py` — API keys, bearer/JWT, GitHub tokens,
  PEM private keys, `.env` assignments, Devin pairing codes (context
  required), emails, absolute user paths.
- `src/devin_redact/engine.py` — `scan()` returns the SPEC §6 contract;
  SQLite cells are scanned read-only, JSON cells are decoded leaf-wise so
  multi-line tool output gets real newlines; `project_name` findings come
  from `sessions.working_directory`. `redact()` is dry-run only
  (`apply=True` raises `NotImplementedError`).
- `src/devin_redact/cli.py` — thin argparse wrapper: `scan`, `redact`
  (dry-run, `--apply` refused), `verify` stub.
- Tests green: 12 passed on Windows (Python 3.11). Recall verified via
  sha256 fingerprints of every planted value; benign file yields zero
  findings; scan is idempotent and read-only (file hashes unchanged, DB
  still opens).

## Remaining for M2

- **In-place SQLite redaction** — masked rewrite of matched cells with
  mandatory backup + single transaction + post-redact open test; only ever
  on a copy unless `--apply --i-know-this-is-irreversible` long flags.
- **Tool-call semantic layer** — use `rawInput` (e.g. `cat .env`,
  `grep` over sensitive files) to flag the *associated* tool output for
  redaction even when the output itself matches no pattern.
- **`verify` subcommand** — exit non-zero / `PUBLICATION STATUS: BLOCKED`
  gate for pre-publish checks.
- Golden-file test for the report; Unicode/encoding edge cases;
  Windows-path edge cases beyond the current corpus.
- `devin-history` integration (export with `--redact` by default), PyPI
  publish, optional `SessionEnd` hook + `/redact` skill.

## Blockers

None.

## Notes / decisions

- `publication_status` semantics: `BLOCKED` if any secret-class finding,
  `REVIEW` if only PII/hygiene findings, `CLEAN` otherwise. The SPEC JSON
  only shows `BLOCKED`; the extra states are additive.
- Findings never contain the secret — only a masked `preview` and a
  sha256 `fingerprint` (16 hex), which also powers the recall tests.
- The real `%APPDATA%\devin\cli\sessions.db` was only ever opened
  read-only to inspect *schema and JSON key paths*. No row content was
  copied; every fixture secret is fabricated (`sk-FAKE…`, `hunter2fake`,
  `ghp_FAKE…`, etc.).
- Pairing-code detection requires explicit context (`pairing code:`) —
  the bare code shape was judged too prone to false positives.
- `.devin/memory/` added to `.gitignore` (local session state).
