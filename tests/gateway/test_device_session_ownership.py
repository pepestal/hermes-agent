"""Device-session ownership contracts for Limen's narrow Hermes capability."""

from gateway.device_credentials import DeviceCredentialStore


def _issued_store(tmp_path):
    store = DeviceCredentialStore(tmp_path / "device-credentials.db", now=lambda: 1_000.0)
    pairing = store.create_pairing("Limen web", expires_in_seconds=60)
    issued = store.consume_pairing(pairing)
    assert issued is not None
    return store, issued


def test_device_can_claim_and_reopen_only_its_own_session(tmp_path):
    store, owner = _issued_store(tmp_path)
    other_pairing = store.create_pairing("Limen Android", expires_in_seconds=60)
    other = store.consume_pairing(other_pairing)
    assert other is not None

    assert store.claim_session(owner.installation_id, "limen_session_1") is True
    assert store.owns_session(owner.installation_id, "limen_session_1") is True
    assert store.owns_session(other.installation_id, "limen_session_1") is False
    assert store.claim_session(other.installation_id, "limen_session_1") is False


def test_device_session_ownership_survives_reopen_and_rejects_revoked_owner(tmp_path):
    path = tmp_path / "device-credentials.db"
    store, owner = _issued_store(tmp_path)
    assert store.claim_session(owner.installation_id, "limen_session_2") is True
    assert store.revoke(owner.installation_id) is True
    store.close()

    reopened = DeviceCredentialStore(path, now=lambda: 1_000.0)
    assert reopened.owns_session(owner.installation_id, "limen_session_2") is False
    assert reopened.claim_session(owner.installation_id, "another_session") is False
