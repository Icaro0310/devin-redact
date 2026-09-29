"""Detection engine — the ``scan`` half of devin-redact.

``scan()`` walks files and SQLite databases, applies the patterns from
:mod:`devin_redact.patterns`, and returns the JSON report contract defined
in ``docs/SPEC.md`` §6. It is strictly read-only: it never opens a database
in write mode and never mutates a file.

``redact()`` is an M1 stub: it performs a dry-run only. In-place SQLite
redaction ships in M2.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path, PurePosixPath

from . import __version__
from .patterns import PATTERNS, SECRET_CATEGORIES, pattern_name, sensitive_match

_DB_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
_BINARY_SNIFF_BYTES = 8192

Finding = dict[str, object]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _mask(value: str) -> str:
    """Lossy preview — never emits the full sensitive value."""
    if "\n" in value:
        value = value.splitlines()[0]
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(text: str, *, file: str, location: str) -> list[Finding]:
    """Apply every pattern to ``text`` and return findings (sorted, deduped)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for category, regexes in PATTERNS.items():
        for index, rx in enumerate(regexes):
            for m in rx.finditer(text):
                value = sensitive_match(m)
                key = (category, pattern_name(category, index), m.start(1) if m.lastindex else m.start())
                if key in seen:
                    continue
                seen.add(key)
                line = _line_of(text, m.start())
                findings.append(
                    {
                        "file": file,
                        "category": category,
                        "pattern": pattern_name(category, index),
                        "location": f"{location}:line {line}",
                        "fingerprint": _fingerprint(value),
                        "preview": _mask(value),
                    }
                )
    return findings


def _iter_files(paths: list[Path]) -> tuple[list[Path], list[Path]]:
    """Expand files/dirs into a sorted file list; second item is skipped dirs."""
    files: set[Path] = set()
    for p in paths:
        if p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
                for name in sorted(names):
                    files.add(Path(root) / name)
        elif p.is_file():
            files.add(p)
    return sorted(files, key=lambda f: str(f).lower()), []


def _looks_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _leaf_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _leaf_strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _leaf_strings(v)]
    return []


def _scan_cell(value: str, display: str, location: str) -> list[Finding]:
    """Scan one text cell. JSON cells are decoded so multi-line payload
    strings (e.g. tool-call output) get real newlines — otherwise
    line-anchored patterns like ``env_assignment`` would miss them."""
    stripped = value.lstrip()
    texts: list[str]
    if stripped.startswith(("{", "[")):
        try:
            texts = _leaf_strings(json.loads(value))
        except (json.JSONDecodeError, RecursionError):
            texts = [value]
    else:
        texts = [value]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for text in texts:
        for f in scan_text(text, file=display, location=location):
            key = (str(f["category"]), str(f["fingerprint"]))
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
    return findings


def _scan_db(path: Path, display: str) -> tuple[list[Finding], list[Finding], str | None]:
    """Scan every TEXT-looking cell of a SQLite DB. Returns (findings,
    project_name_findings, error)."""
    findings: list[Finding] = []
    project_names: list[Finding] = []
    uri = "file:" + str(path.resolve()).replace("\\", "/") + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return findings, project_names, f"sqlite open failed: {exc}"
    try:
        tables = [
            r[0]
            for r in con.execute(
                "select name from sqlite_master where type='table' "
                "and name not like 'sqlite_%' order by name"
            )
        ]
        for table in tables:
            safe_table = table.replace('"', '""')
            try:
                cols = [r[1] for r in con.execute(f'PRAGMA table_info("{safe_table}")')]
                rows = con.execute(f'SELECT rowid, * FROM "{safe_table}"').fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                rowid, cells = row[0], row[1:]
                for col_name, value in zip(cols, cells):
                    if not isinstance(value, str) or not value:
                        continue
                    location = f"{table}.{col_name}#rowid={rowid}"
                    findings.extend(_scan_cell(value, display, location))
                    if (
                        table == "sessions"
                        and col_name == "working_directory"
                        and value
                    ):
                        base = PurePosixPath(value.replace("\\", "/")).name
                        if base:
                            project_names.append(
                                {
                                    "file": display,
                                    "category": "project_name",
                                    "pattern": "working_directory",
                                    "location": location,
                                    "fingerprint": _fingerprint(base),
                                    "preview": _mask(base),
                                }
                            )
    except sqlite3.Error as exc:
        return findings, project_names, f"sqlite scan failed: {exc}"
    finally:
        con.close()
    return findings, project_names, None


def _scan_text_file(path: Path, display: str) -> tuple[list[Finding], str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [], f"read failed: {exc}"
    text = raw.decode("utf-8", errors="replace")
    return scan_text(text, file=display, location="text"), None


def scan(paths) -> dict:
    """Scan files/directories and return the report contract (SPEC §6).

    Deterministic: identical input yields identical output.
    """
    paths = [Path(p) for p in paths]
    files, _ = _iter_files(paths)
    all_findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    scanned = 0

    for f in files:
        display = str(f)
        if f.suffix.lower() in _DB_SUFFIXES:
            findings, proj, err = _scan_db(f, display)
            all_findings.extend(proj)
        elif _looks_binary(f):
            errors.append({"file": display, "error": "skipped: binary file"})
            continue
        else:
            findings, err = _scan_text_file(f, display)
        scanned += 1
        all_findings.extend(findings)
        if err:
            errors.append({"file": display, "error": err})

    all_findings.sort(
        key=lambda x: (str(x["file"]), str(x["location"]), str(x["category"]), str(x["fingerprint"]))
    )

    by_category: dict[str, int] = {}
    for fd in all_findings:
        cat = str(fd["category"])
        by_category[cat] = by_category.get(cat, 0) + 1

    secrets = sum(by_category.get(c, 0) for c in SECRET_CATEGORIES)
    if secrets:
        status = "BLOCKED"
    elif all_findings:
        status = "REVIEW"
    else:
        status = "CLEAN"

    return {
        "tool": "devin-redact",
        "version": __version__,
        "files_scanned": scanned,
        "secrets": secrets,
        "emails": by_category.get("email", 0),
        "absolute_paths": by_category.get("absolute_path", 0),
        "project_names": by_category.get("project_name", 0),
        "findings_total": len(all_findings),
        "by_category": dict(sorted(by_category.items())),
        "publication_status": status,
        "findings": all_findings,
        "errors": errors,
    }


def redact(paths, *, apply: bool = False) -> dict:
    """M1 stub — dry-run only.

    Returns the same findings ``scan()`` would report plus what would be
    redacted, without touching anything. ``apply=True`` is not implemented
    until M2 (in-place SQLite redaction with backup + transaction).
    """
    if apply:
        raise NotImplementedError(
            "in-place redaction ships in M2 — re-run without --apply for a dry-run"
        )
    report = scan(paths)
    return {
        "dry_run": True,
        "applied": False,
        "note": "dry-run only in M1; no file or database was modified",
        "report": report,
    }
