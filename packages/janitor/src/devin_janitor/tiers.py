"""Tiered session classification — the safety core of the janitor.

Every session lands in exactly one tier:

- ``KEEP``        — allowlisted (keep-file ids / title patterns, "não apagar",
                    SLACK-BRAIN), inside the grace window, or substantive work
- ``AUTO_DELETE`` — empty, automation/eval noise, ephemeral heartbeat/mailbox
                    cycles, or a duplicate loser
- ``JUDGE``       — weak but ambiguous signals; deferred to the pluggable
                    judge (default ``none`` keeps them all — fail-open)

Semantics are ported 1:1 from ``legacy/session-janitor.py``.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from devin_janitor.config import JanitorConfig
from devin_janitor.inventory import SessionRow


class Tier(Enum):
    KEEP = "keep"
    AUTO_DELETE = "auto_delete"
    JUDGE = "judge"


@dataclass
class Classification:
    """Result of one classification pass."""

    auto_delete: list[tuple[SessionRow, str]] = field(default_factory=list)
    judge: list[SessionRow] = field(default_factory=list)
    kept: dict[str, str] = field(default_factory=dict)  # id -> reason

    def tier_of(self, session_id: str) -> Tier:
        if session_id in self.kept:
            return Tier.KEEP
        if any(r.id == session_id for r, _ in self.auto_delete):
            return Tier.AUTO_DELETE
        return Tier.JUDGE

    def summary(self) -> dict[str, int]:
        return {
            "keep": len(self.kept),
            "auto_delete": len(self.auto_delete),
            "judge": len(self.judge),
        }


def norm_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]", "", title.lower())[:60]


def load_keep_file(path: str | Path | None) -> tuple[set[str], list[str]]:
    """``{"ids": [...], "title_patterns": [...]}`` — both optional."""
    if path is None:
        return set(), []
    p = Path(path).expanduser()
    if not p.is_file():
        return set(), []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set(), []
    return set(data.get("ids", [])), list(data.get("title_patterns", []))


def classify(
    rows: list[SessionRow],
    config: JanitorConfig | None = None,
    *,
    keep_ids: set[str] | None = None,
    keep_patterns: list[str] | None = None,
    now: float | None = None,
) -> Classification:
    """Assign every row to a tier. ``now`` is epoch seconds (test hook)."""
    cfg = config or JanitorConfig()
    keep_ids = keep_ids or set()
    keep_re = cfg.keep_re(keep_patterns)
    grace_ts = (now if now is not None else time.time()) - cfg.grace_hours * 3600

    result = Classification()

    # Pre-pass: same normalized title within a project → keep the sibling
    # with the most activity, the rest are duplicates.
    by_title: dict[tuple[str, str], list[SessionRow]] = {}
    for r in rows:
        by_title.setdefault((r.project, norm_title(r.title)), []).append(r)
    dup_losers: set[str] = set()
    for sibs in by_title.values():
        if len(sibs) < 2 or not norm_title(sibs[0].title):
            continue
        best = max(sibs, key=lambda x: x.score)
        dup_losers.update(s.id for s in sibs if s.id != best.id)

    for r in rows:
        title = r.title

        if r.id in keep_ids or keep_re.search(title):
            result.kept[r.id] = "allowlist/marked"
            continue
        if r.last_activity and r.last_activity > grace_ts:
            result.kept[r.id] = "grace window"
            continue

        if r.is_empty:
            result.auto_delete.append((r, "empty"))
        elif r.id in dup_losers:
            result.auto_delete.append((r, "duplicate"))
        elif cfg.noise_re.search(title) and r.tool_calls <= cfg.noise_max_tool_calls:
            result.auto_delete.append((r, "automation/eval noise"))
        elif (
            cfg.ephemeral_re.search(title)
            and r.user_msgs <= cfg.ephemeral_max_user_msgs
            and r.tool_calls <= cfg.ephemeral_max_tool_calls
        ):
            result.auto_delete.append((r, "ephemeral heartbeat/mailbox cycle"))
        elif (
            r.user_msgs <= cfg.judge_max_user_msgs
            and r.tool_calls <= cfg.judge_max_tool_calls
            and r.files_touched == 0
            and r.score < cfg.judge_max_score
        ):
            result.judge.append(r)
        else:
            result.kept[r.id] = "substantive work"

    return result
