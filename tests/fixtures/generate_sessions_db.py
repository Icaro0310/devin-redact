"""Deterministically generate ``tests/fixtures/sessions.db``.

The schema mirrors the real Devin CLI ``sessions.db`` (table/column names
only — no real content). Every secret planted here is obviously fake.

Regenerate with::

    python tests/fixtures/generate_sessions_db.py
"""

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("sessions.db")

SCHEMA = """
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  working_directory TEXT NOT NULL,
  backend_type TEXT NOT NULL,
  model TEXT NOT NULL,
  agent_mode TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  title TEXT,
  main_chain_id INTEGER,
  shell_last_seen_index INTEGER DEFAULT 0,
  cogs_json TEXT,
  workspace_dirs TEXT,
  hidden INTEGER NOT NULL DEFAULT 0,
  metadata TEXT
);
CREATE TABLE message_nodes (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  node_id INTEGER NOT NULL,
  parent_node_id INTEGER,
  chat_message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  metadata TEXT,
  UNIQUE(session_id, node_id)
);
CREATE TABLE tool_call_state (
    session_id    TEXT    NOT NULL,
    tool_call_id  TEXT    NOT NULL,
    tool_call_json     TEXT,
    tool_call_update_json TEXT,
    PRIMARY KEY (session_id, tool_call_id)
);
CREATE TABLE prompt_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  is_shell INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE app_state (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE refinery_schema_history(
    version int4 PRIMARY KEY,
    name VARCHAR(255),
    applied_on VARCHAR(255),
    checksum VARCHAR(255));
"""

SESSION_ID = "fixture-session-0001"

USER_MESSAGE = {
    "message_id": "fixture-msg-user-1",
    "role": "user",
    "content": (
        "Here is my fake OpenAI key sk-FAKE0000000000000000000000000000abcd "
        "and my contact fake.user@example.com — fixture data only."
    ),
    "metadata": {"is_user_input": True, "num_tokens": 42},
}

ASSISTANT_MESSAGE = {
    "message_id": "fixture-msg-assistant-1",
    "role": "assistant",
    "content": "Understood — I will not print that key again.",
    "metadata": {"is_user_input": False, "generation_model": "fake-model"},
}

TOOL_CALL = {
    "toolCallId": "tc-fixture-0001",
    "title": "cat .env",
    "kind": "execute",
    "rawInput": {"command": "cat .env", "shell_id": "sh-fixture-1"},
    "locations": [{"path": ".env"}],
    "content": [
        {"type": "content", "content": {"type": "text", "text": "$ cat .env"}}
    ],
}

TOOL_CALL_UPDATE = {
    "toolCallId": "tc-fixture-0001",
    "status": "completed",
    "content": [
        {
            "type": "content",
            "content": {
                "type": "text",
                "text": (
                    "OPENAI_API_KEY=sk-FAKE0000000000000000000000000000abcd\n"
                    "DB_PASSWORD=hunter2fake\n"
                    "GITHUB_TOKEN=ghp_FAKE00000000000000000000\n"
                ),
            },
        }
    ],
}


def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.execute(
        "INSERT INTO sessions (id, working_directory, backend_type, model, "
        "agent_mode, created_at, last_activity_at, title, workspace_dirs, "
        "metadata) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            SESSION_ID,
            r"C:\Users\fakeuser\projects\demo-shop",
            "local",
            "fake-model",
            "normal",
            1700000000,
            1700000060,
            "Fix the demo-shop checkout bug",
            r'["C:\Users\fakeuser\projects\demo-shop"]',
            "{}",
        ),
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, parent_node_id, "
        "chat_message, created_at, metadata) VALUES (?,?,?,?,?,?)",
        (SESSION_ID, 0, None, json.dumps(USER_MESSAGE, sort_keys=True), 1700000001, None),
    )
    con.execute(
        "INSERT INTO message_nodes (session_id, node_id, parent_node_id, "
        "chat_message, created_at, metadata) VALUES (?,?,?,?,?,?)",
        (SESSION_ID, 1, 0, json.dumps(ASSISTANT_MESSAGE, sort_keys=True), 1700000002, None),
    )
    con.execute(
        "INSERT INTO tool_call_state (session_id, tool_call_id, "
        "tool_call_json, tool_call_update_json) VALUES (?,?,?,?)",
        (
            SESSION_ID,
            "tc-fixture-0001",
            json.dumps(TOOL_CALL, sort_keys=True),
            json.dumps(TOOL_CALL_UPDATE, sort_keys=True),
        ),
    )
    con.execute(
        "INSERT INTO prompt_history (content, timestamp, session_id, is_shell) "
        "VALUES (?,?,?,?)",
        (
            "devin pairing code: FAKE-1234-ABCD (synthetic fixture value)",
            1700000003,
            SESSION_ID,
            0,
        ),
    )
    con.execute(
        "INSERT INTO app_state (key, value) VALUES (?,?)",
        ("last_model", "fake-model"),
    )
    con.execute(
        "INSERT INTO refinery_schema_history (version, name, applied_on, checksum) "
        "VALUES (?,?,?,?)",
        (1, "init", "2026-01-01", "fakechecksum"),
    )
    con.commit()
    con.close()
    print(f"wrote {DB_PATH}")


if __name__ == "__main__":
    main()
