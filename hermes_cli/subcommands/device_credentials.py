"""``hermes device`` parser for local device credential lifecycle actions."""
from __future__ import annotations

from typing import Callable


def build_device_parser(subparsers, *, cmd_device: Callable) -> None:
    parser = subparsers.add_parser(
        "device", help="Create or revoke Hermes device credentials",
        description="Local operator-only device pairing and revocation")
    actions = parser.add_subparsers(dest="device_action")

    pair = actions.add_parser("pair", help="Create one short-lived pairing secret")
    pair.add_argument("--label", required=True, help="Human-readable installation label")
    pair.add_argument("--expires-in", type=int, default=300, help="Pairing lifetime in seconds (1-3600)")

    revoke = actions.add_parser("revoke", help="Revoke one device installation")
    revoke.add_argument("installation_id", help="Server-issued installation identity")
    parser.set_defaults(func=cmd_device)
