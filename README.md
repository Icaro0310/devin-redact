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

```bash
pipx install devin-redact
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

## License

MIT — see [LICENSE](LICENSE).
