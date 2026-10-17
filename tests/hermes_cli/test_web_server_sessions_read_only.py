"""Read-only dashboard session-list contract."""

import pytest


@pytest.fixture
def client(monkeypatch, _isolate_hermes_home):
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")

    import hermes_state
    from hermes_constants import get_hermes_home
    from hermes_cli.web_server import app, _SESSION_HEADER_NAME, _SESSION_TOKEN

    monkeypatch.setattr(hermes_state, "DEFAULT_DB_PATH", get_hermes_home() / "state.db")
    test_client = TestClient(app)
    test_client.headers[_SESSION_HEADER_NAME] = _SESSION_TOKEN
    return test_client


def test_get_sessions_read_only_lists_without_auto_archive(client, monkeypatch):
    from hermes_cli.web_routers import sessions as sessions_routes
    from hermes_state import SessionDB

    db = SessionDB()
    try:
        db.create_session("read-only-list", source="cli")
    finally:
        db.close()

    auto_archive_calls = []
    monkeypatch.setattr(
        sessions_routes,
        "_maybe_auto_archive_for_profile",
        lambda profile: auto_archive_calls.append(profile),
    )

    response = client.get("/api/sessions/read-only?limit=50&offset=0")

    assert response.status_code == 200
    assert [row["id"] for row in response.json()["sessions"]] == ["read-only-list"]
    assert auto_archive_calls == []


def test_get_sessions_read_only_refuses_to_initialize_or_repair_store(client, monkeypatch, tmp_path):
    from hermes_cli import web_server_sessions
    from hermes_cli.web_routers import sessions as sessions_routes

    db_path = tmp_path / "strict-state.db"
    assert not db_path.exists()
    monkeypatch.setattr(web_server_sessions, "_session_db_path_for_profile", lambda _profile: db_path)
    auto_archive_calls = []
    monkeypatch.setattr(
        sessions_routes,
        "_maybe_auto_archive_for_profile",
        lambda profile: auto_archive_calls.append(profile),
    )

    missing = client.get("/api/sessions/read-only?limit=50&offset=0")

    assert missing.status_code == 503
    assert not db_path.exists()
    db_path.write_bytes(b"")

    empty = client.get("/api/sessions/read-only?limit=50&offset=0")

    assert empty.status_code == 503
    assert db_path.read_bytes() == b""
    assert auto_archive_calls == []


def test_get_sessions_read_only_refuses_schema_heal(client, monkeypatch, tmp_path):
    from hermes_cli import web_server_sessions
    from hermes_state import SessionDB
    import hermes_state_registry

    db_path = tmp_path / "strict-state.db"
    seed = SessionDB(db_path=db_path)
    seed.close()
    original_bytes = db_path.read_bytes()
    monkeypatch.setattr(web_server_sessions, "_session_db_path_for_profile", lambda _profile: db_path)
    monkeypatch.setattr(
        web_server_sessions,
        "_session_db_read_probe_statements",
        lambda: ('SELECT "sessions"."not_a_real_column" FROM "sessions" LIMIT 0',),
    )

    def writable_open(*_args, **_kwargs):
        raise AssertionError("a read-only session list must not open the store writable")

    monkeypatch.setattr(hermes_state_registry, "acquire", writable_open)

    response = client.get("/api/sessions/read-only?limit=50&offset=0")

    assert response.status_code == 503
    assert db_path.read_bytes() == original_bytes
