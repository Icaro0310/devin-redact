# devin-state

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15339/badge)](https://www.bestpractices.dev/projects/15339)

<!-- DEVIN-ECO:BEGIN -->
> **Part of the [DEVIN ecosystem](https://github.com/Icaro0310/awesome-devin)**  
> Track: Control · Nature: product  
> For: Security engineers, Developers  
> Interface: CLI / Python library  
> Path: Security engineers · step 2/3 — after `devin-backup`, before `devin-janitor`
<!-- DEVIN-ECO:END -->

State safety for Devin Desktop: redact secrets from session stores, back
them up verifiably, and prune sessions behind an export-then-delete
pipeline.

| Package | PyPI | What it does |
|---|---|---|
| [`packages/redact`](packages/redact) | `devin-redact` | Secret and PII redaction with Devin tool-call semantics |
| [`packages/backup`](packages/backup) | `devin-backup` | Snapshots, rotation, integrity checks for Devin stores |
| [`packages/janitor`](packages/janitor) | `devin-janitor` | Session lifecycle janitor with tiered classification |
| [`shared/install-scheduler`](shared/install-scheduler) | `devin-install-scheduler` | Shared cron / Task Scheduler / elapsed install logic |

> **Renamed (Oct 2026):** this repository moved from `Icaro0310/devin-redact` to `Icaro0310/devin-state` when it became the `devin-state` product workspace. PyPI packages and console scripts keep their names; stars, issues and history are preserved by the redirect.

## Layout

```
packages/<name>/   one installable package each (src layout, own tests)
shared/<name>/     internal libraries shared by the packages
tests/integration/ cross-package contract tests
```

Each package ships independently: a tag `redact-vX.Y.Z` (same for
`backup`, `janitor`, `install-scheduler`) publishes only that package.
CI is scoped per path — a change under `packages/backup/` runs only the
backup suite.

## Platform support

All packages support Linux, macOS and Windows; scheduling falls back to
a config-file registry where neither cron nor Task Scheduler exists.
Per-package guides live under `packages/<name>/`.

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.
