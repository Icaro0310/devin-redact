"""Detection + redaction engine.

``scan()`` walks files and SQLite databases, applies the patterns from
:mod:`devin_redact.patterns` (and the tool-call semantics from
:mod:`devin_redact.semantic`), and returns the JSON report contract defined
in ``docs/SPEC.md`` §6. It is strictly read-only: it never opens a database
in write mode and never mutates a file.

``redact()`` performs the same walk but produces masked replacements
(``<REDACTED:sha256prefix>``). It defaults to dry-run; writing requires
``apply=True`` **and** ``confirm_irreversible=True``. SQLite writes are
protected by a mandatory ``.bak`` backup, a single transaction, and a
post-redact open test (rollback + restore on failure).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path, PurePosixPath

from . import __version__
from .patterns import PATTERNS, SECRET_CATEGORIES, pattern_name, sensitive_match
from .semantic import analyze_tool_call_json

_DB_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
_BINARY_SNIFF_BYTES = 8192
_REDACTED_TAG = "<REDACTED:"
_SEMANTIC_CATEGORY = "sensitive_tool_output"
_BLOCKING_CATEGORIES = SECRET_CATEGORIES | {_SEMANTIC_CATEGORY}

Finding = dict[str, object]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _tag(value: str) -> str:
    return f"<REDACTED:{_fingerprint(value)}>"


def _mask(value: str) -> str:
    """Lossy preview — never emits the full sensitive value."""
    if "\n" in value:
        value = value.splitlines()[0]
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _iter_matches(text: str):
    """Yield ``(category, pattern_name, match)`` for every pattern hit."""
    for category, regexes in PATTERNS.items():
        for index, rx in enumerate(regexes):
            for m in rx.finditer(text):
                if _REDACTED_TAG in m.group(0):
                    # Already redacted — don't double-report/re-redact.
                    continue
                yield category, pattern_name(category, index), m


def scan_text(text: str, *, file: str, location: str) -> list[Finding]:
    """Apply every pattern to ``text`` and return findings (sorted, deduped)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for category, name, m in _iter_matches(text):
        value = sensitive_match(m)
        key = (category, name, m.start(1) if m.lastindex else m.start())
        if key in seen:
            continue
        seen.add(key)
        line = _line_of(text, m.start())
        findings.append(
            {
                "file": file,
                "category": category,
                "pattern": name,
                "kind": "pattern",
                "location": f"{location}:line {line}",
                "fingerprint": _fingerprint(value),
                "preview": _mask(value),
            }
        )
    return findings


def redact_text(text: str) -> tuple[str, list[dict]]:
    """Replace every secret span in ``text`` with ``<REDACTED:fp>``.

    ``env_assignment`` matches keep their ``KEY=`` prefix so a redacted
    ``.env`` stays readable. Overlapping matches resolve greedily: the
    leftmost (then longest) span wins. Returns ``(new_text, edits)``.
    Idempotent — ``<REDACTED:…>`` tags are never re-redacted.
    """
    candidates: list[tuple[int, int, str, str, str]] = []
    for category, name, m in _iter_matches(text):
        value = sensitive_match(m)
        fp = _fingerprint(value)
        if category == "env_assignment":
            whole = m.group(0)
            eq = whole.index("=")
            start, end = m.span(0)
            replacement = f"{whole[: eq + 1]}{_tag(value)}"
        else:
            start, end = m.span(1) if m.lastindex else m.span(0)
            replacement = _tag(value)
        candidates.append((start, end, replacement, category, fp))

    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))
    accepted: list[tuple[int, int, str, str, str]] = []
    last_end = -1
    for cand in candidates:
        if cand[0] >= last_end:
            accepted.append(cand)
            last_end = cand[1]

    new_text = text
    edits: list[dict] = []
    for start, end, replacement, category, fp in reversed(accepted):
        new_text = new_text[:start] + replacement + new_text[end:]
        edits.append(
            {
                "category": category,
                "line": _line_of(text, start),
                "fingerprint": fp,
            }
        )
    edits.reverse()
    return new_text, edits


def _iter_files(paths: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for p in paths:
        if p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
                for name in sorted(names):
                    files.add(Path(root) / name)
        elif p.is_file():
            files.add(p)
    return sorted(files, key=lambda f: str(f).lower())


def _looks_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _target_type(path: Path) -> str:
    """Dispatch a scan/redact target: ``"sqlite"``, ``"text"`` or ``"binary"``.

    SQLite stores are detected by extension first (cheap) and then by the
    ``SQLite format 3`` magic header, so derived databases — ``graph.db``,
    ``search.db``, ``memory.db``, ``acp-messages/*.db`` — are scanned as
    databases even when they reach us under an unusual name or no
    extension at all. Anything else that is not binary (``.md`` notes,
    ``.json``/``.jsonl`` exports, ``.env``, plain text) is scanned as text.
    """
    if path.suffix.lower() in _DB_SUFFIXES:
        return "sqlite"
    try:
        with open(path, "rb") as fh:
            head = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return "binary"
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if b"\x00" in head:
        return "binary"
    return "text"


def _leaf_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _leaf_strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _leaf_strings(v)]
    return []


def _redact_leaves(obj) -> tuple[object, list[dict]]:
    """Clone ``obj`` with every string leaf passed through redact_text."""
    edits: list[dict] = []
    if isinstance(obj, str):
        new, edits = redact_text(obj)
        return new, edits
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nv, e = _redact_leaves(v)
            out[k] = nv
            edits.extend(e)
        return out, edits
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, e = _redact_leaves(v)
            out.append(nv)
            edits.extend(e)
        return out, edits
    return obj, edits


# Keys inside `content` subtrees that carry structure, not payload — they
# are preserved so the redacted JSON keeps its acp shape.
_STRUCTURAL_KEYS = frozenset({"type", "mimeType", "toolCallId", "status", "kind"})


def _tag_all_leaves(obj) -> tuple[object, list[str]]:
    """Replace every payload string leaf with its redaction tag; returns
    ``(new_obj, fingerprints_of_replaced_leaves)``. Idempotent."""
    fps: list[str] = []
    if isinstance(obj, str):
        if _REDACTED_TAG in obj:
            return obj, fps
        return _tag(obj), [_fingerprint(obj)]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _STRUCTURAL_KEYS and isinstance(v, str):
                out[k] = v
                continue
            nv, f = _tag_all_leaves(v)
            out[k] = nv
            fps.extend(f)
        return out, fps
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, f = _tag_all_leaves(v)
            out.append(nv)
            fps.extend(f)
        return out, fps
    return obj, fps


def _redact_content_leaves(obj) -> tuple[object, list[dict]]:
    """Wholesale-redact every string leaf inside ``content`` subtrees — the
    semantic-context path for tool output of sensitive reads."""
    edits: list[dict] = []
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "content":
                nv, fps = _tag_all_leaves(v)
                edits.extend(
                    {"category": _SEMANTIC_CATEGORY, "fingerprint": fp} for fp in fps
                )
            else:
                nv, e = _redact_content_leaves(v)
                edits.extend(e)
            out[k] = nv
        return out, edits
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, e = _redact_content_leaves(v)
            out.append(nv)
            edits.extend(e)
        return out, edits
    return obj, edits


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


def _open_ro(path: Path) -> sqlite3.Connection:
    uri = "file:" + str(path.resolve()).replace("\\", "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _db_tables(con: sqlite3.Connection) -> list[str]:
    return [
        r[0]
        for r in con.execute(
            "select name from sqlite_master where type='table' "
            "and name not like 'sqlite_%' order by name"
        )
    ]


def _db_rows(con: sqlite3.Connection, table: str):
    """Yield ``(rowid, {col: value})`` for every row of ``table``."""
    safe = table.replace('"', '""')
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{safe}")')]
    for row in con.execute(f'SELECT rowid, * FROM "{safe}"'):
        yield row[0], dict(zip(cols, row[1:]))


def _semantic_finding(display: str, location: str, flag: dict, output: str) -> Finding:
    return {
        "file": display,
        "category": _SEMANTIC_CATEGORY,
        "pattern": "sensitive_read",
        "kind": "semantic-context",
        "location": location,
        "fingerprint": _fingerprint(output),
        "preview": _mask(output) if output else "(empty output)",
        "reason": flag["reason"],
        "target": flag["target"],
    }


def _scan_db(path: Path, display: str) -> tuple[list[Finding], str | None]:
    """Scan every TEXT-looking cell of a SQLite DB, plus the tool-call
    semantic layer over ``tool_call_state``."""
    findings: list[Finding] = []
    try:
        con = _open_ro(path)
    except sqlite3.Error as exc:
        return findings, f"sqlite open failed: {exc}"
    try:
        for table in _db_tables(con):
            try:
                rows = list(_db_rows(con, table))
            except sqlite3.Error:
                continue
            for rowid, cells in rows:
                for col_name, value in cells.items():
                    if not isinstance(value, str) or not value:
                        continue
                    location = f"{table}.{col_name}#rowid={rowid}"
                    findings.extend(_scan_cell(value, display, location))
                    if (
                        table == "sessions"
                        and col_name == "working_directory"
                        and _REDACTED_TAG not in value
                    ):
                        base = PurePosixPath(value.replace("\\", "/")).name
                        if base:
                            findings.append(
                                {
                                    "file": display,
                                    "category": "project_name",
                                    "pattern": "working_directory",
                                    "kind": "metadata",
                                    "location": location,
                                    "fingerprint": _fingerprint(base),
                                    "preview": _mask(base),
                                }
                            )
                if table == "tool_call_state":
                    call_json = cells.get("tool_call_json")
                    update_json = cells.get("tool_call_update_json")
                    if not isinstance(call_json, str):
                        continue
                    flag = analyze_tool_call_json(call_json)
                    if flag and isinstance(update_json, str):
                        location = f"{table}.tool_call_update_json#rowid={rowid}"
                        if _REDACTED_TAG not in update_json:
                            findings.append(
                                _semantic_finding(display, location, flag, update_json)
                            )
    except sqlite3.Error as exc:
        return findings, f"sqlite scan failed: {exc}"
    finally:
        con.close()
    return findings, None


def _scan_text_file(path: Path, display: str) -> tuple[list[Finding], str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [], f"read failed: {exc}"
    text = raw.decode("utf-8", errors="replace")
    return scan_text(text, file=display, location="text"), None


def _summarize(findings: list[Finding]) -> tuple[dict[str, int], int, str]:
    by_category: dict[str, int] = {}
    for fd in findings:
        cat = str(fd["category"])
        by_category[cat] = by_category.get(cat, 0) + 1
    secrets = sum(by_category.get(c, 0) for c in _BLOCKING_CATEGORIES)
    if secrets:
        status = "BLOCKED"
    elif findings:
        status = "REVIEW"
    else:
        status = "CLEAN"
    return dict(sorted(by_category.items())), secrets, status


def scan(paths) -> dict:
    """Scan files/directories and return the report contract (SPEC §6).

    Deterministic: identical input yields identical output.
    """
    files = _iter_files([Path(p) for p in paths])
    all_findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    scanned = 0

    for f in files:
        display = str(f)
        kind = _target_type(f)
        if kind == "sqlite":
            findings, err = _scan_db(f, display)
        elif kind == "binary":
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
    by_category, secrets, status = _summarize(all_findings)

    return {
        "tool": "devin-redact",
        "version": __version__,
        "files_scanned": scanned,
        "secrets": secrets,
        "emails": by_category.get("email", 0),
        "absolute_paths": by_category.get("absolute_path", 0),
        "project_names": by_category.get("project_name", 0),
        "findings_total": len(all_findings),
        "by_category": by_category,
        "publication_status": status,
        "findings": all_findings,
        "errors": errors,
    }


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


def _plan_cell(value: str, semantic_output: bool) -> tuple[str | None, list[dict]]:
    """Return ``(new_value, edits)`` or ``(None, [])`` when unchanged."""
    stripped = value.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            obj = json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            new, edits = redact_text(value)
            return (new, edits) if edits else (None, [])
        if semantic_output:
            new_obj, edits = _redact_content_leaves(obj)
        else:
            new_obj, edits = _redact_leaves(obj)
        if not edits:
            return None, []
        return json.dumps(new_obj, ensure_ascii=False), edits
    if semantic_output:
        if _REDACTED_TAG in value:
            return None, []
        return _tag(value), [{"category": _SEMANTIC_CATEGORY, "fingerprint": _fingerprint(value)}]
    new, edits = redact_text(value)
    return (new, edits) if edits else (None, [])


def _plan_db(path: Path, display: str) -> tuple[list[dict], str | None]:
    """Plan cell updates for a SQLite DB."""
    cell_edits: list[dict] = []
    try:
        con = _open_ro(path)
    except sqlite3.Error as exc:
        return cell_edits, f"sqlite open failed: {exc}"
    try:
        for table in _db_tables(con):
            try:
                rows = list(_db_rows(con, table))
            except sqlite3.Error:
                continue
            for rowid, cells in rows:
                semantic_cols: set[str] = set()
                if table == "tool_call_state":
                    flag = analyze_tool_call_json(str(cells.get("tool_call_json") or ""))
                    if flag:
                        semantic_cols.add("tool_call_update_json")
                for col_name, value in cells.items():
                    if not isinstance(value, str) or not value:
                        continue
                    new_value, edits = _plan_cell(value, col_name in semantic_cols)
                    if new_value is None:
                        continue
                    cell_edits.append(
                        {
                            "table": table,
                            "column": col_name,
                            "rowid": rowid,
                            "new_value": new_value,
                            "edits": edits,
                        }
                    )
    except sqlite3.Error as exc:
        return cell_edits, f"sqlite scan failed: {exc}"
    finally:
        con.close()
    return cell_edits, None


def _backup(path: Path) -> Path:
    bak = path.with_name(path.name + ".bak")
    shutil.copy2(path, bak)
    for side in (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if side.exists():
            shutil.copy2(side, side.with_name(side.name + ".bak"))
    return bak


def _update_cell(con: sqlite3.Connection, edit: dict) -> None:
    con.execute(
        f'UPDATE "{edit["table"].replace(chr(34), chr(34) * 2)}" '
        f'SET "{edit["column"].replace(chr(34), chr(34) * 2)}" = ? WHERE rowid = ?',
        (edit["new_value"], edit["rowid"]),
    )


def _apply_db(path: Path, cell_edits: list[dict]) -> None:
    """Apply cell updates in one transaction; rollback + restore on failure."""
    _backup(path)
    con = sqlite3.connect(path)
    try:
        con.execute("BEGIN")
        for edit in cell_edits:
            _update_cell(con, edit)
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()
    # Post-redact open test: the DB must still parse.
    try:
        chk = _open_ro(path)
        (ok,) = chk.execute("PRAGMA integrity_check").fetchone()
        chk.execute("SELECT count(*) FROM sqlite_master").fetchone()
        chk.close()
        if ok != "ok":
            raise sqlite3.DatabaseError(f"integrity_check: {ok}")
    except sqlite3.Error:
        bak = path.with_name(path.name + ".bak")
        shutil.copy2(bak, path)
        raise


def _apply_text(path: Path, new_text: str) -> None:
    _backup(path)
    path.write_text(new_text, encoding="utf-8")


def redact(paths, *, apply: bool = False, confirm_irreversible: bool = False) -> dict:
    """Redact findings. Dry-run by default.

    ``apply=True`` writes masked replacements in place and requires
    ``confirm_irreversible=True`` (the CLI's ``--apply
    --i-know-this-is-irreversible``). Every modified file gets a ``.bak``
    sibling backup; DB writes run in a single transaction with a
    post-redact open test.
    """
    if apply and not confirm_irreversible:
        raise RuntimeError(
            "in-place redaction requires confirm_irreversible=True "
            "(CLI: --apply --i-know-this-is-irreversible)"
        )

    files = _iter_files([Path(p) for p in paths])
    planned: list[dict] = []  # per-file plans
    edit_log: list[dict] = []
    errors: list[dict[str, str]] = []

    for f in files:
        display = str(f)
        kind = _target_type(f)
        if kind == "sqlite":
            cell_edits, err = _plan_db(f, display)
            if err:
                errors.append({"file": display, "error": err})
                continue
            if cell_edits:
                planned.append({"kind": "db", "path": f, "cells": cell_edits})
                for cell in cell_edits:
                    for e in cell["edits"]:
                        edit_log.append(
                            {
                                "file": display,
                                "location": f"{cell['table']}.{cell['column']}#rowid={cell['rowid']}",
                                **e,
                            }
                        )
        elif kind == "binary":
            errors.append({"file": display, "error": "skipped: binary file"})
            continue
        else:
            try:
                raw = f.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                errors.append({"file": display, "error": f"read failed: {exc}"})
                continue
            new_text, edits = redact_text(text)
            if edits:
                planned.append({"kind": "text", "path": f, "new_text": new_text})
                for e in edits:
                    edit_log.append({"file": display, "location": f"line {e['line']}", **{k: v for k, v in e.items() if k != "line"}})

    result = {
        "dry_run": not apply,
        "applied": apply,
        "files_scanned": len(files),
        "files_changed": len(planned),
        "replacements": len(edit_log),
        "edits": sorted(edit_log, key=lambda e: (str(e["file"]), str(e["location"]))),
        "errors": errors,
        "backups": [],
    }

    if not apply:
        result["note"] = "dry-run — no file or database was modified"
        return result

    for plan in planned:
        path: Path = plan["path"]
        try:
            if plan["kind"] == "db":
                _apply_db(path, plan["cells"])
            else:
                _apply_text(path, plan["new_text"])
            result["backups"].append(str(path.with_name(path.name + ".bak")))
        except Exception as exc:
            errors.append({"file": str(path), "error": f"apply failed: {exc}"})
            result["applied_ok"] = False
    result.setdefault("applied_ok", not errors)
    return result
