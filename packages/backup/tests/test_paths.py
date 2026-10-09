import sqlite3
from pathlib import Path

from devin_backup.stores import default_config_dir, default_data_dir, discover_stores


def test_linux_defaults_split_data_and_config_roots(tmp_path):
    env = {"XDG_DATA_HOME": str(tmp_path / "data"), "XDG_CONFIG_HOME": str(tmp_path / "config")}

    assert default_data_dir(environ=env, platform="linux") == (
        Path(env["XDG_DATA_HOME"]) / "devin"
    )
    assert default_config_dir(environ=env, platform="linux") == (
        Path(env["XDG_CONFIG_HOME"]) / "Devin"
    )


def test_discovery_includes_a_separate_config_root(tmp_path):
    data_root = tmp_path / "data" / "devin"
    config_root = tmp_path / "config" / "Devin"
    data_db = data_root / "cli" / "sessions.db"
    acp_db = config_root / "User" / "acp-messages" / "session.db"
    state_db = config_root / "User" / "globalStorage" / "state.vscdb"
    for db in (data_db, acp_db, state_db):
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE sample (value TEXT)")

    stores = discover_stores(data_root, config_dir=config_root)
    found = {(store.root, store.rel_path) for store in stores}

    assert ("data", "cli/sessions.db") in found
    assert ("config", "User/acp-messages/session.db") in found
    assert ("config", "User/globalStorage/state.vscdb") in found
