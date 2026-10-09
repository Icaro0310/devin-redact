"""SessionEnd hook support (RD-1).

``run_hook()`` resolves the just-ended session — ``--session-id`` flag,
then a ``{"session_id": ...}`` JSON payload on stdin, then
``DEVIN_SESSION_ID``, then the most recently active session in
``sessions.db`` — scans only that session's rows (messages, tool-call
state, prompt history) and writes the verdict to a **side file** under
``<data-dir>/redact/<session-id>.json``.

Fail-soft by design: it never writes into any Devin store or transcript
and never blocks session teardown — an unresolvable session produces a
``SKIPPED`` verdict and the CLI still exits 0. Only usage errors (e.g.
a ``--sessions-db`` path that is not a file) exit non-zero.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, engine, paths

# Side-file name used when no session id could be resolved at all.
_UNRESOLVED_NAME = "_unresolved.json"

# Cap on the hook payload read from stdin.
_STDIN_CAP = 1 << 20


def resolve_session_id(
    *,
    flag: str | None,
    stdin_text: str | None,
    environ: dict[str, str],
    db_path: Path | None,
) -> tuple[str | None, str]:
    """Resolve the session to scan; returns ``(session_id, source)``.

    Precedence: ``--session-id`` flag → ``{"session_id": ...}`` JSON on
    stdin → ``DEVIN_SESSION_ID`` → most recently active in ``sessions.db``.
    """
    if flag and str(flag).strip():
        return str(flag).strip(), "flag"
    if stdin_text:
        try:
            payload = json.loads(stdin_text)
        except (json.JSONDecodeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            sid = payload.get("session_id")
            if isinstance(sid, str) and sid.strip():
                return sid.strip(), "stdin"
    env_id = (environ or {}).get("DEVIN_SESSION_ID")
    if env_id and env_id.strip():
        return env_id.strip(), "env"
    if db_path is not None:
        sid = engine.latest_session_id(db_path)
        if sid:
            return sid, "latest"
    return None, "none"


def default_out(data_dir: Path, session_id: str | None) -> Path:
    """``<data-dir>/redact/<session-id>.json`` side-file location."""
    name = f"{session_id}.json" if session_id else _UNRESOLVED_NAME
    return Path(data_dir) / "redact" / name


def run_hook(
    *,
    session_id: str | None = None,
    sessions_db: Path | str | None = None,
    data_dir: Path | str | None = None,
    out: Path | str | None = None,
    stdin_text: str | None = None,
    environ: dict[str, str] | None = None,
) -> dict:
    """Resolve, scan and write the session-end verdict side file.

    Always returns the verdict dict; store problems degrade to a
    ``SKIPPED`` verdict, never an exception.
    """
    environ = os.environ if environ is None else environ
    db = (
        Path(sessions_db)
        if sessions_db is not None
        else paths.default_sessions_db(environ=environ)
    )
    sid, source = resolve_session_id(
        flag=session_id, stdin_text=stdin_text, environ=environ, db_path=db
    )
    base_dir = (
        Path(data_dir)
        if data_dir is not None
        else paths.default_data_dir(environ=environ, sessions_db=db)
    )
    out_path = Path(out) if out is not None else default_out(base_dir, sid)

    verdict: dict = {
        "tool": "devin-redact",
        "version": __version__,
        "hook": "session-end",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": sid,
        "session_id_source": source,
        "sessions_db": str(db) if db is not None else None,
        "verdict_file": str(out_path),
        "publication_status": "SKIPPED",
        "reason": None,
        "secrets": 0,
        "findings_total": 0,
        "by_category": {},
        "findings": [],
        "errors": [],
    }

    if sid is None:
        verdict["reason"] = (
            "could not resolve a session id (--session-id, stdin "
            "{\"session_id\": …}, DEVIN_SESSION_ID, or sessions.db)"
        )
    elif db is None:
        verdict["reason"] = "no sessions.db found on this machine"
    elif not db.is_file():
        verdict["reason"] = f"sessions.db is not a file: {db}"
    else:
        exists = engine.session_exists(db, sid)
        if exists is False:
            verdict["reason"] = f"session {sid!r} not found in {db}"
        else:
            try:
                report = engine.scan_session(db, sid)
            except Exception as exc:  # noqa: BLE001 - fail-soft: never break teardown
                verdict["reason"] = f"scan failed: {exc}"
            else:
                verdict.update(
                    {
                        "publication_status": report["publication_status"],
                        "secrets": report["secrets"],
                        "findings_total": report["findings_total"],
                        "by_category": report["by_category"],
                        "findings": report["findings"],
                        "errors": report["errors"],
                    }
                )
                if report["errors"] and report["publication_status"] == "CLEAN":
                    # The scan could not cover the store — never claim
                    # CLEAN on an unreadable/corrupt sessions.db.
                    verdict["publication_status"] = "SKIPPED"
                    verdict["reason"] = (
                        f"scan incomplete: {report['errors'][0]['error']}"
                    )

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        blob = json.dumps(verdict, indent=2, sort_keys=True, ensure_ascii=True)
        out_path.write_text(blob + "\n", encoding="utf-8")
    except OSError as exc:
        verdict["errors"].append(
            {"file": str(out_path), "error": f"verdict write failed: {exc}"}
        )
    return verdict
