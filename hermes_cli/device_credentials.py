"""Local, explicit operator actions for Hermes device credentials."""
from __future__ import annotations

from gateway.device_credentials import DeviceCredentialStore
from hermes_constants import get_hermes_home


def _store() -> DeviceCredentialStore:
    return DeviceCredentialStore(get_hermes_home() / "device_credentials.db")


def device_credential_command(args) -> None:
    """Create pairing material or revoke one installation; secrets print once only."""
    action = getattr(args, "device_action", None)
    store = _store()
    if action == "pair":
        label = str(getattr(args, "label", "") or "").strip()
        expires_in = getattr(args, "expires_in", None)
        if not label or not isinstance(expires_in, int) or not 1 <= expires_in <= 3600:
            raise ValueError("pair requires a non-empty label and --expires-in between 1 and 3600")
        # This is intentionally the sole plaintext display of the pairing bearer.
        print(store.create_pairing(label, expires_in_seconds=expires_in))
        return
    if action == "revoke":
        installation_id = str(getattr(args, "installation_id", "") or "").strip()
        if not installation_id:
            raise ValueError("revoke requires an installation ID")
        if not store.revoke(installation_id):
            raise ValueError("active installation not found or is currently writing an event")
        print("revoked")
        return
    raise ValueError("Usage: hermes device {pair|revoke}")
