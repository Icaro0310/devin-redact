<div align="center">

<img src="assets/banner.svg" alt="devin-redact" width="100%"/>

</div>

# devin-redact

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.

**[Português (BR)](README.pt-BR.md)** · English

Secret and PII redaction that understands Devin tool-call semantics —
in-place in `sessions.db`, not just flat text.

## The problem

Agent transcripts accumulate secrets: `cat .env` in a tool's output, keys
pasted into chat, tokens inside error messages. Publishing or sharing those
sessions leaks credentials. This is not hypothetical: during the audit that
motivated this project, a **real Devin CLI pairing code** was found sitting
inside a prompt in the local history.

## Prior art

- **geheim** — redacts secrets from Claude Code transcripts before sharing.
- **agent-leaks** — audits agent session logs (JSONL) for leaked credentials.
- **AgentLogs** — tooling around inspecting/exporting agent session logs.

These tools target Claude Code / Codex-style **JSONL files**. None of them
reads Devin's `sessions.db`, and none of them knows that a `cat .env` tool
call and its output are the same event. `devin-redact` adapts the idea; it
does not reinvent it.

## What makes it Devin-native

1. **Side-by-side:** it reads *and* will write the SQLite session store
   (`sessions.db`, `acp-messages/*.db`) — the tools above can only chew on
   flat files and cannot tell a command (`rawInput`) from its output.
2. **No-Devin:** remove Devin and the extra disappears — there is no
   `tool_call_state`, no `message_nodes`, no pairing codes.
3. **One sentence:** *it's the only cleaner that understands which commands
   ran and cleans the database, not just the text.*

`scan` opens the DB read-only, decodes `tool_call_json` /
`tool_call_update_json` / `chat_message` payloads and finds secrets inside
tool inputs *and* outputs. On top of pattern matching, the semantic layer
reads `tool_call_state.rawInput`: when the command touched a known-sensitive
file (`cat .env`, `type credentials.toml`, a read tool pointing at
`~/.ssh/…`), its output is flagged as `kind="semantic-context"` even when
the output matches no pattern. `redact` rewrites those cells in place —
masked as `<REDACTED:sha256prefix>` — keeping the JSON valid, inside a
single transaction with a mandatory `.bak` backup and a post-redact open
test.

## Install

Python ≥ 3.10 and `pipx` are required. **Windows (PowerShell):** install `pipx` with `py -m pip install --user pipx`, run `py -m pipx ensurepath`, then reopen the terminal. **Linux (Debian/Ubuntu):** run `sudo apt install pipx python3-venv` and `pipx ensurepath`; reopen the terminal. Other Linux distributions should install `pipx` using their package manager.

```bash
pipx install "devin-redact @ git+https://github.com/Icaro0310/devin-redact.git"
```

For development:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

```bash
# Read-only scan — prints the JSON report (SPEC §6 contract)
devin-redact scan path/to/sessions.db exports/ .env

# Same, plus write the report to a file
devin-redact scan sessions.db --report report.json

# SARIF 2.1.0 for CI / code-scanning ingestion (never contains secret text)
devin-redact scan sessions.db --format sarif > scan.sarif

# Dry-run redact — shows exactly what would change, modifies nothing
devin-redact redact sessions.db

# In-place redact (long flag on purpose; writes .bak backups first)
devin-redact redact sessions.db --apply --i-know-this-is-irreversible

# Publication gate: exit 0 only when CLEAN, else 1
devin-redact verify sessions.db exports/
devin-redact verify sessions.db --json
```

Report shape (deterministic — same input, same output):

```json
{"files_scanned": 4, "secrets": 20, "emails": 3,
 "absolute_paths": 5, "project_names": 1,
 "publication_status": "BLOCKED", "findings": [...]}
```

`publication_status` is `BLOCKED` when any secret-class finding exists,
`REVIEW` when only PII/hygiene findings exist, `CLEAN` when nothing was
found. Findings carry a masked `preview` and a `fingerprint`
(sha256, first 16 hex) — the report itself never contains the secret.

Detection categories: API keys (OpenAI/Stripe/AWS/Google/Slack shapes),
bearer tokens and JWTs, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`,
`ghr_`, `github_pat_`), PEM private keys, `.env`-style assignments to
sensitive variable names, Devin pairing codes, email addresses, and absolute
user paths (`C:\Users\…`, `/home/…`, `/Users/…`).

`scan --format sarif` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log instead of the JSON report: one rule descriptor per detection category,
one result per finding with its file location (`region.startLine` for text
files; the `table.column#rowid` SQLite locator is preserved in
`properties.location`), a masked message like `match: aws access key id`,
and the sha256 fingerprint as `partialFingerprints` for deduplication.
Secret-class categories map to `level: error`, PII/hygiene to `warning`.
The log never contains the matched secret text, so it is safe to upload to
code-scanning dashboards or archive as a CI artifact.

## What gets scanned

Targets can be files or directories; directories are walked recursively.
Every file is dispatched by type — detected by extension **or** by content:

- **SQLite stores** (`.db`/`.sqlite`/`.sqlite3`, *or any file starting with
  the `SQLite format 3` magic header*) are opened read-only and every text
  column of every table is scanned. This covers Devin's `sessions.db` and
  `User/acp-messages/*.db`, plus the derived stores that inherit session
  text: [`devin-graph`](https://github.com/Icaro0310/devin-graph)'s
  `graph.db`, [`devin-search`](https://github.com/Icaro0310/devin-search)'s
  `search.db` (FTS5 `docs` included) and
  [`devin-memory`](https://github.com/Icaro0310/devin-memory)'s
  `memory.db`. On `sessions.db`-shaped data the tool-call semantic layer
  and `project_name` extraction also apply; other stores get the generic
  text-column scan.
- **Text files** — `.md` notes (including a `devin-history` export dir,
  whose notes are named `<YYYY-MM-DD>_<session-id>.md`), `.json`/`.jsonl`
  exports, `.env`, logs — are scanned whole; findings carry a line number.
- **Binary files** are skipped and reported under `errors`.

`redact` uses the same dispatch: derived SQLite stores are rewritable under
`--apply` with the same `.bak` + transaction + integrity-check guarantees
as `sessions.db`.

## Works with Devin alone (Devin-only mode)

The default `scan` is read-only and fully offline. `--apply` rewrites Devin's
SQLite store in place — it writes `.bak` backups first, and running
[`devin-backup`](https://github.com/Icaro0310/devin-backup) beforehand is the
recommended extra safety net. Detection is heuristic: review the report
before applying.

## Platform support

Pure stdlib Python — identical behavior on Windows, Linux and macOS. CI runs
the suite on `windows-latest` + `ubuntu-latest`; the target database is
always an explicit argument, so there are no platform-specific paths.

## Limitations

- **False negatives exist.** This is a pattern-based scanner, not a guarantee.
  Secrets in unusual formats, encodings, or split across chunks will be
  missed. Run `gitleaks`/`trufflehog` too — this complements them, it does
  not replace them.
- **False positives exist.** Keyword-based `.env` matching can flag benign
  assignments; pairing codes are only flagged with explicit context.
- **Private internals.** `sessions.db` schema and the `chisel`/`acp` JSON
  shapes are undocumented and can change between Devin CLI versions. The
  scanner reads cells generically to be resilient, but a schema change can
  still reduce recall.
- **Not preventive.** It finds secrets *after* they landed in the transcript.
  Stopping the agent from reading secrets is policy work, not redaction work.
- **Redaction is destructive by design.** `--apply` always writes a `.bak`
  sibling first and DB updates run in one transaction with a post-redact
  open test — but once you publish/share a `.bak`-less tree, the secrets
  that were in it are the only copy. Keep backups safe.
- **Semantic layer is heuristic.** The sensitive-file table covers common
  names (`.env*`, `credentials*`, `*.pem`, `~/.ssh`, `~/.aws`, …); a
  secret-bearing file with an unusual name read via `cat` will not be
  flagged — pattern matching still applies to its output.
- **M2 scope.** `scan`, `redact` and `verify` work. Still out:
  `devin-history` integration, PyPI publish, `SessionEnd` hook, `/redact`
  skill.

## When to use this

- You are about to share or publish Devin session data — an export, a bug
  report, a demo database — and need to scrub secrets and PII first.
- You want a pre-publish gate: `devin-redact verify` exits 0 only when the
  target is `CLEAN`, so it drops straight into CI.
- You need redaction inside `sessions.db` itself, not just in exported
  text — it rewrites the SQLite cells in place.
- You want findings a flat regex scanner misses: a `cat .env` tool call
  flags its output as sensitive via `tool_call_state.rawInput` even when
  the output matches no pattern.

## When NOT to use this

- You need a guarantee that no secret survives — pattern-based scanning has
  false negatives; run `gitleaks`/`trufflehog` alongside it.
- You want to stop secrets from entering transcripts in the first place —
  that is agent policy work, not redaction work.
- You cannot accept a destructive write — `--apply` rewrites cells in
  place; run [`devin-backup`](https://github.com/Icaro0310/devin-backup)
  first and review the dry-run.

## FAQ

**What is devin-redact?** A scanner and redactor for Devin's session
stores. `scan` reads `sessions.db` (and export files) read-only and reports
secrets, emails, absolute paths and project names; `redact --apply` masks
findings in place as `<REDACTED:sha256prefix>`; `verify` gates publication
with an exit code.

**Is scanning safe to run against my live database?** Yes — `scan` opens
the database read-only and never modifies it. Only `redact --apply` writes,
and it creates a `.bak` sibling first inside a single transaction with a
post-redact open test.

**What does the publication verdict mean?** `publication_status` is
`BLOCKED` when any secret-class finding exists, `REVIEW` when only
PII/hygiene findings exist, and `CLEAN` when nothing was found. `verify`
exits 0 only on `CLEAN`. The report carries masked previews and sha256
fingerprints — never the secret itself.

**Will it catch every secret?** No. It is a heuristic, pattern-based
scanner plus a semantic layer for sensitive-file reads — unusual formats,
encodings or secrets split across chunks will be missed. Treat it as a
strong complement to `gitleaks`/`trufflehog`, not a replacement.

## License

MIT — see [LICENSE](LICENSE).
