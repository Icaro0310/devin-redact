# Snapshot manifest contract

`manifest.json` in every snapshot directory is a **public contract**:
`devin-janitor`'s tier-3 guard consumes it to refuse GUI-state deletion
unless a fresh, verified snapshot exists. Treat breaking changes as a
cross-repo API break — janitor re-implements verification on its side.

## Fields janitor requires

| field | rule |
|---|---|
| `manifest_version` | integer; janitor accepts `{1, 2}` — bump requires a janitor-side update |
| `created_at` | ISO-8601 timestamp, parseable, < 24h old at cleanup time |
| `files` | list of entries |
| `files[].path` | store path; a file whose basename is `state.vscdb` must be listed for tier-3 coverage (exact name match — `state.vscdb.old` does not count) |
| `files[].snapshot_path` | optional; when present, the file lives at `snapshot/<snapshot_path>` instead of `snapshot/<path>` |
| `files[].size` | when present, must equal the file's byte size |
| `files[].sha256` | when present, must equal the file's SHA-256 |

The consumer-side semantics live in
`devin-janitor/src/devin_janitor/cleanup.py::verify_snapshot`. Producer
compliance is pinned by `tests/test_janitor_contract.py` — a manifest
that drifts from this table fails devin-backup's own suite.

## Versioning

- Additive fields are safe: janitor ignores unknown keys.
- Removing or renaming a required field, or bumping `manifest_version`
  past 2 without updating janitor's `SUPPORTED_MANIFEST_VERSIONS`,
  breaks the tier-3 guard — coordinate across both repos.
- This contract is deliberately kept as documentation + tests, not a
  shared package: two repos, one seam, per the ecosystem rule that
  helper extraction needs evidence.
