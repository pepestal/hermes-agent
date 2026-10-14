"""Admission boundaries for Limen device credentials on session resources."""

from pathlib import Path

import pytest

from gateway.config import PlatformConfig
from gateway.device_credentials import DeviceCredentialStore
from gateway.platforms import api_server, api_server_runs
from gateway.platforms.api_server import APIServerAdapter


class _Request(dict):
    def __init__(self, authorization: str):
        super().__init__()
        self.headers = {"Authorization": authorization}
        self.method = "GET"
        self.path_qs = "/api/sessions"
        self.remote = "127.0.0.1"
        self.transport = None


def _adapter_with_two_devices(tmp_path: Path):
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": "operator-secret-1234"}))
    store = DeviceCredentialStore(tmp_path / "device-credentials.db", now=lambda: 1_000.0)
    first_pairing = store.create_pairing("Limen web", expires_in_seconds=60)
    first = store.consume_pairing(first_pairing)
    second_pairing = store.create_pairing("Limen Android", expires_in_seconds=60)
    second = store.consume_pairing(second_pairing)
    assert first is not None and second is not None
    adapter._device_credential_store = store
    return adapter, store, first, second


def test_device_bearer_is_admitted_only_on_session_gate(tmp_path):
    adapter, _store, issued, _other = _adapter_with_two_devices(tmp_path)
    request = _Request(f"Bearer {issued.credential}")

    assert adapter._check_session_auth(request) is None
    assert adapter._device_installation(request) == issued.installation_id
    # Generic gateway auth deliberately remains operator-key only.
    assert adapter._check_auth(request).status == 401


def test_operator_key_with_device_prefix_retains_session_and_run_access(tmp_path):
    operator_key = "hdev_operator-key-123456789"
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={"key": operator_key}))
    request = _Request(f"Bearer {operator_key}")

    assert adapter._check_session_auth(request) is None
    assert adapter._device_installation(request) == ""
    assert adapter._check_run_auth(request, permission="dispatch") is None


def test_device_session_gate_hides_another_installation_session(tmp_path):
    adapter, store, first, second = _adapter_with_two_devices(tmp_path)
    assert store.claim_session(first.installation_id, "limen_session_1") is True

    owner_request = _Request(f"Bearer {first.credential}")
    other_request = _Request(f"Bearer {second.credential}")
    assert adapter._check_session_auth(owner_request) is None
    assert adapter._check_session_auth(other_request) is None

    assert adapter._device_owns_session_or_404(owner_request, "limen_session_1") is None
    denied = adapter._device_owns_session_or_404(other_request, "limen_session_1")
    assert denied is not None
    assert denied.status == 404


def test_revoked_device_is_rejected_before_session_resource_handler(tmp_path):
    adapter, store, issued, _other = _adapter_with_two_devices(tmp_path)
    assert store.revoke(issued.installation_id) is True

    response = adapter._check_session_auth(_Request(f"Bearer {issued.credential}"))
    assert response is not None
    assert response.status == 401


def test_device_run_scope_isolated_per_installation(tmp_path):
    adapter, store, first, second = _adapter_with_two_devices(tmp_path)
    assert store.claim_session(first.installation_id, "limen_session_3") is True
    first_request = _Request(f"Bearer {first.credential}")
    second_request = _Request(f"Bearer {second.credential}")
    assert adapter._check_run_auth(first_request, permission="dispatch") is None
    assert adapter._check_run_auth(second_request, permission="dispatch") is None

    assert adapter._run_idempotency_scope(first_request) != adapter._run_idempotency_scope(second_request)


def test_device_rejects_foreign_previous_response_before_history_load(tmp_path):
    adapter, store, first, second = _adapter_with_two_devices(tmp_path)
    assert store.claim_session(first.installation_id, "owned-session") is True
    assert store.claim_session(second.installation_id, "foreign-session") is True
    adapter._response_store.put("resp_foreign", {
        "session_id": "foreign-session",
        "conversation_history": [{"role": "user", "content": "secret foreign history"}],
    })

    history, _instructions, stored_session_id, error = api_server_runs._resolve_conversation_history(
        adapter,
        {"previous_response_id": "resp_foreign", "session_id": "owned-session"},
        "hello",
        _openai_error=lambda message, **_kwargs: {"message": message},
        response_session_allowed=lambda session_id: (
            session_id == "owned-session" and store.owns_session(first.installation_id, session_id)),
    )
    assert history == []
    assert stored_session_id is None
    assert error is not None


class _Response:
    def __init__(self):
        self.writes = []

    async def write(self, data):
        self.writes.append(data)


@pytest.mark.asyncio
async def test_revoked_device_cannot_write_another_sse_frame(tmp_path):
    adapter, store, issued, _other = _adapter_with_two_devices(tmp_path)
    request = _Request(f"Bearer {issued.credential}")
    assert adapter._check_run_auth(request, permission="status") is None
    response = _Response()

    await api_server_runs._write_device_scoped_stream(adapter, request, response, b"first", _api_server=api_server)
    assert response.writes == [b"first"]
    assert store.revoke(issued.installation_id) is True

    with pytest.raises(api_server_runs._DeviceStreamRevoked):
        await api_server_runs._write_device_scoped_stream(adapter, request, response, b"later", _api_server=api_server)
    assert response.writes == [b"first"]
