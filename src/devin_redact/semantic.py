"""Tool-call semantic layer.

Knows *which commands ran*, not just what bytes look like secrets. When a
``tool_call_state.tool_call_json`` says the agent ran ``cat .env`` (or any
read of a known-sensitive file), the associated ``tool_call_update_json``
output is flagged for redaction even when no pattern matches its content —
e.g. an ``.env`` full of innocuous-looking values, or a private key in an
unusual format.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

# Shell verbs whose stdout reflects file content (or pipes of it).
_READ_VERBS = frozenset(
    {
        "cat",
        "type",
        "more",
        "less",
        "head",
        "tail",
        "grep",
        "rg",
        "findstr",
        "get-content",
        "gc",
        "sed",
        "awk",
        "bat",
        "xxd",
        "od",
        "strings",
        "cp",
        "copy",
    }
)

# Exact basenames that are sensitive regardless of location.
_SENSITIVE_BASENAMES = frozenset(
    {
        ".env",
        ".envrc",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".htpasswd",
        ".pgpass",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "credentials.toml",
        "credentials.json",
        "mcp_config.json",
        "auth.json",
        "token.json",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "secrets.toml",
    }
)

# Extensions that mark key material / secret stores.
_SENSITIVE_SUFFIXES = frozenset(
    {".env", ".pem", ".key", ".keystore", ".jks", ".p12", ".pfx", ".kdbx", ".asc"}
)

# Path segments that mark sensitive directories.
_SENSITIVE_SEGMENTS = frozenset({".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure"})

_SPLIT = re.compile(r"[|;&>\s]+")


def is_sensitive_path(token: str) -> bool:
    """True when a path-like token points at a known-sensitive file."""
    token = token.strip().strip("\"'`")
    if not token:
        return False
    norm = token.replace("\\", "/")
    base = PurePosixPath(norm).name.lower()
    if not base:
        return False
    if base in _SENSITIVE_BASENAMES or base.startswith(".env"):
        return True
    if PurePosixPath(base).suffix.lower() in _SENSITIVE_SUFFIXES:
        return True
    if "credential" in base or "secret" in base:
        return True
    segments = {seg.lower() for seg in norm.split("/")}
    return bool(segments & _SENSITIVE_SEGMENTS)


def analyze_tool_call(tool_call: dict) -> dict | None:
    """Return a flag dict when the tool call reads a sensitive file.

    ``tool_call`` is the parsed ``tool_call_json`` (acp ToolCall shape):
    ``kind`` == ``"execute"`` means a shell command in ``rawInput.command``;
    other kinds carry direct paths in ``rawInput.path`` / ``rawInput.query``.
    """
    raw = tool_call.get("rawInput")
    if not isinstance(raw, dict):
        return None
    title = str(tool_call.get("title") or "")

    if tool_call.get("kind") == "execute":
        command = str(raw.get("command") or title)
        tokens = [t for t in _SPLIT.split(command) if t]
        if not any(t.lower() in _READ_VERBS for t in tokens):
            return None
        target = next((t for t in tokens if is_sensitive_path(t)), None)
        if target is None:
            return None
        return {
            "reason": "shell command reads a sensitive file",
            "command": command[:120],
            "target": target,
        }

    for key in ("path", "query"):
        value = raw.get(key)
        if isinstance(value, str) and is_sensitive_path(value):
            return {
                "reason": f"tool input {key!r} targets a sensitive file",
                "command": title[:120],
                "target": value,
            }
    return None


def analyze_tool_call_json(tool_call_json: str) -> dict | None:
    """Parse ``tool_call_json`` text and analyze it; None if unparseable."""
    try:
        tool_call = json.loads(tool_call_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(tool_call, dict):
        return None
    return analyze_tool_call(tool_call)
