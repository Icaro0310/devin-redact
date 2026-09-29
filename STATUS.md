# STATUS

## Milestone M2 — done (2026-09-29)

- `src/devin_redact/semantic.py` — tool-call semantic layer. Parses
  `tool_call_state.tool_call_json` `rawInput`; when `kind == "execute"`
  requires a read-verb token (`cat`, `type`, `grep`, `rg`, `Get-Content`,
  …) plus a sensitive-path token; non-shell tool calls are flagged via
  `rawInput.path`/`query`. Sensitivity table: basenames (`.env*`,
  `.netrc`, `id_*`, `credentials*`, `mcp_config.json`, `secrets.*`, …),
  suffixes (`.pem`, `.key`, `.p12`, `.kdbx`, …) and dir segments
  (`.ssh`, `.aws`, `.gnupg`, `.docker`, `.kube`, `.azure`).
  Flagged outputs surface as findings with `kind="semantic-context"` and
  `category="sensitive_tool_output"` (blocks publication).
- `engine.redact()` — real implementation:
  - Secret spans → `<REDACTED:sha256prefix>` (fp = first 16 hex of the
    sha256 of the matched value; matches the scan-report fingerprint).
  - `env_assignment` keeps the `NAME=` prefix so redacted dotfiles stay
    readable.
  - JSON cells are decoded and rewritten leaf-wise — structure stays
    valid. Semantically-flagged tool outputs are wholesale-redacted
    inside `content` subtrees while structural keys
    (`type`, `mimeType`, `toolCallId`, `status`, `kind`) are preserved.
  - Write safety: dry-run by default; `apply` requires
    `confirm_irreversible` (CLI: `--apply --i-know-this-is-irreversible`);
    every modified file gets a `<name>.bak` sibling; DB updates run in a
    single transaction; post-redact reopen + `PRAGMA integrity_check`,
    restoring the backup on failure.
  - Idempotent: `<REDACTED:…>` tags are skipped by both `scan` and
    `redact` (re-running reports zero replacements).
- CLI `verify` — exit 0 only when `CLEAN`, else 1 with
  `PUBLICATION STATUS: …` + per-category summary; `--json` emits the full
  scan report.
- Fixtures: `sessions.db` regenerated with `tc-fixture-0002`
  (`cat .env` → output with NO pattern-shaped secret — only the semantic
  layer flags it) and `tc-fixture-0003` (`ls -la`, negative control).
- Tests: 23 green on Windows / Python 3.11 — redact-on-copy (DB opens,
  planted fingerprints gone, `verify` → 0), induced-failure rollback,
  semantic flagging/negative control, verify exit codes, idempotency.

## Done criteria check

- `python -m pytest` — 23 passed.
- `verify` on dirty fixture → exit 1 (`PUBLICATION STATUS: BLOCKED`).
- `verify` on a redacted copy → exit 0 (`CLEAN`).

## Remaining for M3

- `devin-history` integration (export with `--redact` by default).
- PyPI publish (`pipx install devin-redact`).
- Optional `SessionEnd` hook + `/redact` skill.
- Candidates/edges noted during M2:
  - `chat_message` `metadata.extensions.chisel/tool_call_content.*` also
    embeds `rawInput`/`status` in the real store — the semantic layer only
    reads `tool_call_state` today.
  - Golden-file report test; Unicode/encoding edge cases; more
    Windows-path shapes (`%USERPROFILE%`, UNC).
  - `.bak` files keep the original secrets — verify scanning a directory
    that contains `.bak` files will still flag them (expected; document
    for users or add a `--ignore-backups` option).

## Blockers

None.

## Notes / decisions

- `verify` is strict: any finding (secret-class or PII/hygiene) exits 1.
  Rationale: it's a publication gate — publishable trees should be
  `CLEAN`, not merely "no secrets".
- Semantic flagging fires on `tool_call_state` rows even when the output
  already contains pattern matches (tc-fixture-0001 is both). Dedup of
  pattern vs. semantic findings on the same cell is by category+fingerprint,
  so no double-count of the same secret value.
- `sensitive_tool_output` counts as a secret-class (blocking) category.
