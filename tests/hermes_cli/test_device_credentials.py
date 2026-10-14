from argparse import Namespace
from unittest.mock import patch

from gateway.device_credentials import DeviceCredentialStore
from hermes_cli.device_credentials import device_credential_command


def test_local_operator_can_create_and_revoke_a_device_pairing(tmp_path, capsys):
    store = DeviceCredentialStore(tmp_path / "device-credentials.db")
    with patch("hermes_cli.device_credentials._store", return_value=store):
        device_credential_command(
            Namespace(device_action="pair", label="Limen Android", expires_in=90, installation_id=None)
        )
        pairing = capsys.readouterr().out.strip()
        assert pairing.startswith("hpair_")

        issued = store.consume_pairing(pairing)
        assert issued is not None
        device_credential_command(
            Namespace(device_action="revoke", label=None, expires_in=None, installation_id=issued.installation_id)
        )
    assert store.authenticate(issued.credential) is None
