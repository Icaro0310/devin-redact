# STATUS

## RD-1 / RD-2 / RD-4 — done (2026-10-04)

- `src/devin_redact/paths.py` — default `sessions.db` discovery, same
  candidate order as `devin-history` (APPDATA → macOS Library →
  XDG_DATA_HOME → XDG_CONFIG_HOME → home).
- Cross-chunk pass (RD-2, `engine._scan_chunked`): on
  `sessions.db`-shaped stores, re-scans concatenations of adjacent
  same-session payloads — `tool_call_json`+`tool_call_update_json` of the
  same row, adjacent `tool_call_state`/`message_nodes` rows, and leaves
  inside one payload (streaming splits). Findings get
  `kind="cross-chunk"`, are reported at the earlier rowid and carry
  `combined_with` for the later locator. Bounded by a cheap boundary
  pre-filter (`_split_boundary_candidate`): the full pattern suite only
  runs on a pair when one side ends mid-secret-shape — secrets split
  across sessions or non-adjacent rows stay undetected (documented).
  Detection-only: `redact` still masks per-cell and cannot split a
  reassembled secret back into two halves — those findings need manual
  review.
- CLI `sessionend-scan` (RD-1): scan-only invocation for the planned
  `devin-powerups` `tools/hooks_dispatch.py` SessionEnd handler. Auto-
  detects the default `sessions.db`, prints exactly
  `devin-redact: findings=N publication_status=X`, exits 0 even on
  BLOCKED; 2 only on hard error (missing explicit path, unreadable
  target). `docs/HOOKS.md` carries the `hooks.json` registration entry.
- CLI `gate` (RD-4): prints just `CLEAN`/`REVIEW`/`BLOCKED`; exits
  0/0/1/2 (hard error = report errors other than binary skips). The
  top-level `publication_status` field was already in the `scan --format
  json` report — verified, now documented as the devin-history contract.
- Tests: 63 green on Linux / Python 3.14 — split-secret fixtures across
  message nodes, tool-call rows (adjacent, within-row, streamed parts),
  cross-session + non-adjacent negatives, hook/gate exit codes and the
  verdict-line regex.
- CLI `session-end` (RD-1, spec'd variant): resolves the just-ended
  session (`--session-id` → stdin `{"session_id": …}` →
  `DEVIN_SESSION_ID` → most recently active), scans only its rows via
  `engine.scan_session()` and writes the verdict to a side file —
  `<data-dir>/redact/<session-id>.json` (`--data-dir`,
  `DEVIN_REDACT_DATA_DIR`, `--out` overrides). Never touches a Devin
  store; fail-soft SKIPPED/exit 0. Coexists with `sessionend-scan`
  (whole-store verdict line) — two hook shapes, pick per need.
- CLI `verify-publish` (RD-4, export cross-reference): enumerates a
  `devin-history` export dir via `index.json`/`index.md`/filename
  layout, resolves each `session_id`, scans every file read-only and
  cross-references `session-end` side files — `BLOCKED` hook verdict +
  `CLEAN` export → warning + overall `REVIEW`. Exit 0 only on `CLEAN`.
- `engine.scan_session()` / `session_exists()` / `latest_session_id()`:
  session-scoped scanning filters every table by `session_id` (or
  `sessions.id`); the `sessions` row itself is skipped so clean sessions
  stay `CLEAN` (project_name/absolute_path hygiene findings are
  whole-store concerns, not per-message).
- Cross-chunk pre-filter hardened: a boundary-spanning token-run ≥ 12
  chars triggers the reassembly scan unconditionally — secrets split at
  *any* byte offset (even 1-char fragments) are now detected; `Bearer`/
  `KEY=`/`pairing code` context edges relaxed. Verified by an
  every-offset sweep over api_key/GitHub/AWS/JWT shapes.
- Tests: 100 green — every-offset split sweep, session-end resolution
  chain/fail-soft/side-file guarantees, verify-publish over both export
  layouts + hook cross-reference, index.md wikilinks, missing entries.

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

- `devin-history` integration — wire `gate`/`publication_status` into the
  exporter (scan before export; `--redact` by default).
- PyPI publish (`pipx install devin-redact`).
- `/redact` skill.
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
