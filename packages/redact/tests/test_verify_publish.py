"""RD-4: ``devin-redact verify-publish`` — gate a devin-history export dir.

Cross-references redaction findings with export state: the exported
sessions are enumerated from ``index.json``/``index.md`` (or the
``<YYYY-MM-DD>_<session-id>.<ext>`` layout), each is scanned read-only,
and per-session verdicts are reported — nothing ships while secrets
remain. ``session-end`` verdict side files are cross-referenced too.
"""

import json
from pathlib import Path

from devin_redact import cli, publish
from test_scan import FAKE_API_KEY, FAKE_GITHUB_TOKEN

DIRTY_SID = "sess-dirty1"
CLEAN_SID = "sess-clean1"


def _md_note(sid: str, body: str, title: str = "t") -> str:
    return (
        "---\n"
        f"session_id: {sid}\n"
        "last_activity: 1700000000\n"
        "tags: [session, devin, history]\n"
        "---\n\n"
        f"# {title}\n\n{body}\n"
    )


def _json_dump(sid: str, body: str) -> str:
    return json.dumps(
        {
            "session_id": sid,
            "title": "t",
            "last_activity": 1700000000,
            "messages": [{"role": "user", "text": body}],
        },
        indent=2,
    )


def _index_json(entries: list[dict]) -> str:
    return json.dumps(
        {
            "provenance": {"machine_id": "m", "profile": "p"},
            "stats": {"total": len(entries)},
            "sessions": entries,
        },
        indent=2,
    )


def _export_dir(tmp_path: Path) -> Path:
    """devin-history md layout: index.json + one clean + one dirty note."""
    out = tmp_path / "export"
    out.mkdir()
    dirty = f"2026-05-28_{DIRTY_SID}.md"
    clean = f"2026-05-29_{CLEAN_SID}.md"
    (out / dirty).write_text(
        _md_note(DIRTY_SID, "used key " + FAKE_API_KEY), encoding="utf-8"
    )
    (out / clean).write_text(_md_note(CLEAN_SID, "all clean"), encoding="utf-8")
    (out / "index.json").write_text(
        _index_json(
            [
                {"date": "2026-05-28", "file": dirty, "title": "dirty",
                 "project": "p", "user_msgs": 1, "assistant_msgs": 0,
                 "tool_msgs": 0},
                {"date": "2026-05-29", "file": clean, "title": "clean",
                 "project": "p", "user_msgs": 1, "assistant_msgs": 0,
                 "tool_msgs": 0},
            ]
        ),
        encoding="utf-8",
    )
    return out


def test_verify_publish_blocked(tmp_path, capsys):
    out = _export_dir(tmp_path)
    code = cli.main(["verify-publish", str(out)])
    assert code == 1
    text = capsys.readouterr().out
    assert "PUBLICATION STATUS: BLOCKED" in text
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    by_sid = {s["session_id"]: s for s in report["sessions"]}
    assert by_sid[DIRTY_SID]["publication_status"] == "BLOCKED"
    assert by_sid[CLEAN_SID]["publication_status"] == "CLEAN"
    assert report["index"] == "index.json"
    assert report["sessions_total"] == 2


def test_verify_publish_clean_export(tmp_path, capsys):
    out = tmp_path / "export"
    out.mkdir()
    name = f"2026-05-29_{CLEAN_SID}.md"
    (out / name).write_text(_md_note(CLEAN_SID, "no secrets"), encoding="utf-8")
    code = cli.main(["verify-publish", str(out)])
    assert code == 0
    assert "PUBLICATION STATUS: CLEAN" in capsys.readouterr().out


def test_verify_publish_json_report(tmp_path, capsys):
    out = _export_dir(tmp_path)
    code = cli.main(["verify-publish", str(out), "--json"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["publication_status"] == "BLOCKED"
    assert report["sessions_blocked"] == 1
    assert report["sessions_clean"] == 1


def test_no_index_falls_back_to_filenames(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    (out / f"2026-05-28_{DIRTY_SID}.json").write_text(
        _json_dump(DIRTY_SID, "token " + FAKE_GITHUB_TOKEN), encoding="utf-8"
    )
    (out / f"2026-05-29_{CLEAN_SID}.json").write_text(
        _json_dump(CLEAN_SID, "fine"), encoding="utf-8"
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert report["index"] is None
    sids = {s["session_id"] for s in report["sessions"]}
    assert sids == {DIRTY_SID, CLEAN_SID}
    assert report["publication_status"] == "BLOCKED"


def test_index_md_layout(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    note = f"2026-05-28_{DIRTY_SID}.md"
    (out / note).write_text(
        _md_note(DIRTY_SID, "key " + FAKE_API_KEY), encoding="utf-8"
    )
    (out / "index.md").write_text(
        "---\ntags: [index]\n---\n\n# Session index\n\n"
        "## p\n\n"
        f"- [[{note[:-3]}|2026-05-28 — dirty]]\n",
        encoding="utf-8",
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert report["index"] == "index.md"
    assert report["sessions_total"] == 1
    assert report["sessions"][0]["session_id"] == DIRTY_SID
    assert report["sessions"][0]["publication_status"] == "BLOCKED"


def test_index_file_itself_not_scanned_as_session(tmp_path):
    out = _export_dir(tmp_path)
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    names = {s["file"] for s in report["sessions"]}
    assert "index.json" not in names


def test_hook_verdict_cross_reference(tmp_path):
    """A BLOCKED session-end verdict beside a CLEAN export → warning."""
    out = tmp_path / "export"
    out.mkdir()
    (out / f"2026-05-29_{CLEAN_SID}.md").write_text(
        _md_note(CLEAN_SID, "clean export"), encoding="utf-8"
    )
    verdicts = tmp_path / "redact"
    verdicts.mkdir()
    (verdicts / f"{CLEAN_SID}.json").write_text(
        json.dumps({"session_id": CLEAN_SID, "publication_status": "BLOCKED"}),
        encoding="utf-8",
    )
    report = publish.verify_publish(out, verdicts_dir=verdicts)
    rec = report["sessions"][0]
    assert rec["publication_status"] == "CLEAN"
    assert rec["hook_status"] == "BLOCKED"
    assert report["warnings"], "expected a cross-reference warning"
    assert report["publication_status"] == "REVIEW"


def test_hook_verdict_clean_when_export_blocked(tmp_path):
    out = _export_dir(tmp_path)
    verdicts = tmp_path / "redact"
    verdicts.mkdir()
    (verdicts / f"{DIRTY_SID}.json").write_text(
        json.dumps({"session_id": DIRTY_SID, "publication_status": "BLOCKED"}),
        encoding="utf-8",
    )
    report = publish.verify_publish(out, verdicts_dir=verdicts)
    rec = {s["session_id"]: s for s in report["sessions"]}[DIRTY_SID]
    assert rec["publication_status"] == "BLOCKED"
    assert rec["hook_status"] == "BLOCKED"
    assert report["warnings"] == []
    assert report["publication_status"] == "BLOCKED"


def test_missing_index_entry_flagged(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    (out / "index.json").write_text(
        _index_json(
            [
                {"date": "2026-05-28", "file": f"2026-05-28_{DIRTY_SID}.md",
                 "title": "gone", "project": "p", "user_msgs": 1,
                 "assistant_msgs": 0, "tool_msgs": 0},
            ]
        ),
        encoding="utf-8",
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert report["sessions"][0]["publication_status"] == "MISSING"
    assert report["publication_status"] == "REVIEW"
    assert report["warnings"]


def test_missing_dir_is_usage_error(tmp_path, capsys):
    assert cli.main(["verify-publish", str(tmp_path / "nope")]) == 2
    assert "devin-redact:" in capsys.readouterr().err


def test_verify_publish_is_read_only(tmp_path):
    out = _export_dir(tmp_path)
    before = {p: p.read_bytes() for p in out.iterdir()}
    publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    for p, blob in before.items():
        assert p.read_bytes() == blob


def test_redacted_export_scans_clean(tmp_path):
    out = tmp_path / "export"
    out.mkdir()
    (out / f"2026-05-29_{CLEAN_SID}.md").write_text(
        _md_note(CLEAN_SID, "used key <REDACTED:0123456789abcdef>"),
        encoding="utf-8",
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert report["publication_status"] == "CLEAN"
