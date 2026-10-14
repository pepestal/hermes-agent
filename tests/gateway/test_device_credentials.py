"""Security contract for the durable Limen device-credential registry.

The store is deliberately independent of HTTP routes so pairing, issuance,
revocation and restart behavior can be proven with disposable state before an API
surface is admitted.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.device_credentials import DeviceCredentialStore


def test_pairing_secret_is_consumed_once_and_plain_values_are_never_persisted(tmp_path):
    store = DeviceCredentialStore(tmp_path / "device-credentials.db", now=lambda: 1_000.0)

    pairing_secret = store.create_pairing("Limen web", expires_in_seconds=60)
    issued = store.consume_pairing(pairing_secret)

    assert issued is not None
    assert issued.installation_id.startswith("device_")
    assert issued.credential.startswith("hdev_")
    assert store.consume_pairing(pairing_secret) is None

    raw = (tmp_path / "device-credentials.db").read_bytes()
    assert pairing_secret.encode() not in raw
    assert issued.credential.encode() not in raw
    for suffix in ("-wal", "-shm"):
        artifact = tmp_path / f"device-credentials.db{suffix}"
        if artifact.exists():
            payload = artifact.read_bytes()
            assert pairing_secret.encode() not in payload
            assert issued.credential.encode() not in payload


def test_concurrent_pairing_consumption_issues_exactly_one_device_credential(tmp_path):
    db_path = tmp_path / "device-credentials.db"
    seed = DeviceCredentialStore(db_path, now=lambda: 1_000.0)
    pairing_secret = seed.create_pairing("Phone", expires_in_seconds=60)
    stores = [DeviceCredentialStore(db_path, now=lambda: 1_000.0) for _ in range(8)]
    barrier = threading.Barrier(len(stores))

    def consume_once(store):
        barrier.wait()
        return store.consume_pairing(pairing_secret)

    with ThreadPoolExecutor(max_workers=len(stores)) as workers:
        results = list(workers.map(consume_once, stores))

    issued = [result for result in results if result is not None]
    assert len(issued) == 1
    assert issued[0].installation_id.startswith("device_")


def test_revocation_and_expiry_fail_closed_across_registry_reopen(tmp_path):
    current = [1_000.0]
    db_path = tmp_path / "device-credentials.db"
    store = DeviceCredentialStore(
        db_path,
        now=lambda: current[0],
        credential_ttl_seconds=1,
    )
    issued = store.consume_pairing(store.create_pairing("Browser", expires_in_seconds=10))
    assert issued is not None

    reopened = DeviceCredentialStore(
        db_path,
        now=lambda: current[0],
        credential_ttl_seconds=1,
    )
    principal = reopened.authenticate(issued.credential)
    assert principal is not None
    assert principal.installation_id == issued.installation_id
    assert reopened.revoke(issued.installation_id) is True
    assert reopened.authenticate(issued.credential) is None
    assert reopened.revoke(issued.installation_id) is False

    active = store.consume_pairing(store.create_pairing("Expiry", expires_in_seconds=10))
    assert active is not None
    expired_pairing = store.create_pairing("Expired browser", expires_in_seconds=1)
    current[0] += 2
    assert store.authenticate(active.credential) is None
    assert store.consume_pairing(expired_pairing) is None


def test_registry_rejects_malformed_or_unknown_credentials_without_raising(tmp_path):
    store = DeviceCredentialStore(tmp_path / "device-credentials.db", now=lambda: 1_000.0)

    for value in ("", "Bearer hdev_not-a-token", "hdev_", "hdev_" + "x" * 10_000):
        assert store.authenticate(value) is None


def test_registry_unavailability_fails_closed(tmp_path):
    store = DeviceCredentialStore(tmp_path / "device-credentials.db", now=lambda: 1_000.0)
    issued = store.consume_pairing(store.create_pairing("Browser", expires_in_seconds=10))
    assert issued is not None

    store.close()

    assert store.authenticate(issued.credential) is None
