"""Durable, device-scoped credentials for independently deployed Hermes clients.

This module owns only pairing, issuance, lookup and revocation. HTTP admission and
session/run authorization are deliberately separate follow-up slices. Plain pairing
secrets and bearer credentials exist only at issuance/consumption boundaries; SQLite
holds fixed SHA-256 lookups, not reversibly stored values or an unbounded password-hash
collection. SHA-256 is appropriate here because these values are server-generated,
high-entropy bearer secrets; it is never used for a human-chosen secret.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator


_PAIRING_PREFIX = "hpair_"
_CREDENTIAL_PREFIX = "hdev_"
_MAX_SECRET_LENGTH = 512
_MAX_LABEL_LENGTH = 128
_MAX_SESSION_ID_LENGTH = 256
_DEFAULT_CREDENTIAL_TTL_SECONDS = 30 * 24 * 60 * 60
_STREAM_LEASE_TTL_SECONDS = 60


@dataclass(frozen=True)
class IssuedDeviceCredential:
    """One-time return value for a successful pairing consumption."""

    installation_id: str
    credential: str
    expires_at: float


@dataclass(frozen=True)
class DevicePrincipal:
    """Non-secret credential identity used by later API authorization layers."""

    installation_id: str
    expires_at: float


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DeviceCredentialStore:
    """Atomic device-pairing and credential lifecycle backed by a bounded SQLite registry."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        now: Callable[[], float] = time.time,
        credential_ttl_seconds: int = _DEFAULT_CREDENTIAL_TTL_SECONDS,
    ) -> None:
        if credential_ttl_seconds <= 0:
            raise ValueError("credential_ttl_seconds must be positive")
        self._path = Path(db_path)
        self._now = now
        self._credential_ttl_seconds = credential_ttl_seconds
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=30)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS device_pairings (
                pairing_hash TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS device_credentials (
                installation_id TEXT PRIMARY KEY,
                credential_hash TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL
            )"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS device_credentials_active_lookup "
                           "ON device_credentials(credential_hash, revoked_at, expires_at)")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS device_session_owners (
                session_id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES device_credentials(installation_id),
                claimed_at REAL NOT NULL
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS device_stream_leases (
                lease_id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL REFERENCES device_credentials(installation_id),
                expires_at REAL NOT NULL
            )"""
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS device_stream_leases_expiry "
                           "ON device_stream_leases(expires_at)")
        self._conn.commit()
        self._tighten_permissions()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _tighten_permissions(self) -> None:
        for candidate in (self._path, self._path.with_name(self._path.name + "-wal"), self._path.with_name(self._path.name + "-shm")):
            try:
                if candidate.exists():
                    candidate.chmod(0o600)
            except OSError:
                pass

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    @staticmethod
    def _new_secret(prefix: str) -> str:
        return prefix + secrets.token_urlsafe(32)

    @staticmethod
    def _normal_label(label: str) -> str:
        normalized = str(label or "").strip()
        if not normalized:
            raise ValueError("device label is required")
        if len(normalized) > _MAX_LABEL_LENGTH or any(ord(char) < 32 for char in normalized):
            raise ValueError("device label is invalid")
        return normalized

    @staticmethod
    def _valid_secret(value: str, prefix: str) -> bool:
        return (
            isinstance(value, str)
            and value.startswith(prefix)
            and len(value) > len(prefix)
            and len(value) <= _MAX_SECRET_LENGTH
            and value.isascii()
        )

    def create_pairing(self, label: str, *, expires_in_seconds: int) -> str:
        """Create one short-lived pairing secret. The plaintext is returned once, never stored."""
        if expires_in_seconds <= 0:
            raise ValueError("expires_in_seconds must be positive")
        clean_label = self._normal_label(label)
        now = float(self._now())
        secret = self._new_secret(_PAIRING_PREFIX)
        with self._transaction():
            self._conn.execute("DELETE FROM device_pairings WHERE expires_at <= ? OR consumed_at IS NOT NULL", (now,))
            self._conn.execute(
                "INSERT INTO device_pairings(pairing_hash,label,expires_at,consumed_at) VALUES(?,?,?,NULL)",
                (_digest(secret), clean_label, now + float(expires_in_seconds)),
            )
        self._tighten_permissions()
        return secret

    def consume_pairing(self, pairing_secret: str) -> IssuedDeviceCredential | None:
        """Atomically consume a pairing secret and return one new device bearer credential."""
        if not self._valid_secret(pairing_secret, _PAIRING_PREFIX):
            return None
        now = float(self._now())
        pairing_hash = _digest(pairing_secret)
        credential = self._new_secret(_CREDENTIAL_PREFIX)
        installation_id = "device_" + secrets.token_hex(16)
        expires_at = now + float(self._credential_ttl_seconds)
        with self._transaction():
            row = self._conn.execute(
                "SELECT label, expires_at, consumed_at FROM device_pairings WHERE pairing_hash=?",
                (pairing_hash,),
            ).fetchone()
            if row is None or row[2] is not None or float(row[1]) <= now:
                return None
            changed = self._conn.execute(
                "UPDATE device_pairings SET consumed_at=? WHERE pairing_hash=? AND consumed_at IS NULL AND expires_at > ?",
                (now, pairing_hash, now),
            ).rowcount
            if changed != 1:
                return None
            self._conn.execute(
                """INSERT INTO device_credentials(
                    installation_id,credential_hash,label,issued_at,expires_at,revoked_at
                ) VALUES(?,?,?,?,?,NULL)""",
                (installation_id, _digest(credential), str(row[0]), now, expires_at),
            )
        self._tighten_permissions()
        return IssuedDeviceCredential(installation_id=installation_id, credential=credential, expires_at=expires_at)

    def authenticate(self, credential: str) -> DevicePrincipal | None:
        """Return a non-secret device principal only for active, unexpired credentials."""
        if not self._valid_secret(credential, _CREDENTIAL_PREFIX):
            return None
        now = float(self._now())
        credential_hash = _digest(credential)
        try:
            with self._lock:
                row = self._conn.execute(
                    """SELECT installation_id, credential_hash, expires_at
                         FROM device_credentials
                        WHERE credential_hash=? AND revoked_at IS NULL AND expires_at > ?""",
                    (credential_hash, now),
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None or not hmac.compare_digest(str(row[1]), credential_hash):
            return None
        return DevicePrincipal(installation_id=str(row[0]), expires_at=float(row[2]))

    @contextmanager
    def active_credential_lease(self, credential: str) -> Iterator[DevicePrincipal | None]:
        """Acquire a cross-process SQLite lease for exactly one pending SSE write.

        A revocation may succeed only after all active durable leases are released.
        The lease does not hold a Python mutex across an ``await``; a process crash is
        bounded by its expiry and therefore cannot block revocation indefinitely.
        """
        if not self._valid_secret(credential, _CREDENTIAL_PREFIX):
            yield None
            return
        now = float(self._now())
        lease_id = secrets.token_urlsafe(24)
        try:
            with self._transaction():
                self._conn.execute("DELETE FROM device_stream_leases WHERE expires_at <= ?", (now,))
                row = self._conn.execute(
                    """SELECT installation_id, expires_at FROM device_credentials
                         WHERE credential_hash=? AND revoked_at IS NULL AND expires_at > ?""",
                    (_digest(credential), now),
                ).fetchone()
                principal = (
                    DevicePrincipal(installation_id=str(row[0]), expires_at=float(row[1]))
                    if row else None
                )
                if principal is not None:
                    self._conn.execute(
                        "INSERT INTO device_stream_leases(lease_id,installation_id,expires_at) VALUES(?,?,?)",
                        (lease_id, principal.installation_id, now + _STREAM_LEASE_TTL_SECONDS),
                    )
        except sqlite3.Error:
            yield None
            return
        try:
            yield principal
        finally:
            try:
                with self._transaction():
                    self._conn.execute("DELETE FROM device_stream_leases WHERE lease_id=?", (lease_id,))
            except sqlite3.Error:
                # A later lease cleanup is safe; fail closed for subsequent writes.
                pass

    def revoke(self, installation_id: str) -> bool:
        """Revoke an active device credential exactly once; repeat revocation is a safe no-op."""
        if not isinstance(installation_id, str) or not installation_id.startswith("device_") or len(installation_id) > 128:
            return False
        now = float(self._now())
        with self._transaction():
            self._conn.execute("DELETE FROM device_stream_leases WHERE expires_at <= ?", (now,))
            changed = self._conn.execute(
                """UPDATE device_credentials SET revoked_at=?
                     WHERE installation_id=? AND revoked_at IS NULL
                       AND NOT EXISTS (
                           SELECT 1 FROM device_stream_leases
                            WHERE installation_id=device_credentials.installation_id
                       )""",
                (now, installation_id),
            ).rowcount
        return changed == 1

    @staticmethod
    def _valid_session_id(session_id: str) -> bool:
        return (
            isinstance(session_id, str)
            and bool(session_id)
            and len(session_id) <= _MAX_SESSION_ID_LENGTH
            and not any(ord(char) < 32 for char in session_id)
        )

    def claim_session(self, installation_id: str, session_id: str) -> bool:
        """Atomically bind a newly created session to one active device installation.

        Repeating the same claim is idempotent; another installation can never transfer
        ownership. Callers must still authenticate the bearer before passing its principal.
        """
        if not self._valid_session_id(session_id):
            return False
        now = float(self._now())
        try:
            with self._transaction():
                active = self._conn.execute(
                    """SELECT 1 FROM device_credentials
                         WHERE installation_id=? AND revoked_at IS NULL AND expires_at > ?""",
                    (installation_id, now),
                ).fetchone()
                if active is None:
                    return False
                existing = self._conn.execute(
                    "SELECT installation_id FROM device_session_owners WHERE session_id=?", (session_id,)
                ).fetchone()
                if existing is not None:
                    return hmac.compare_digest(str(existing[0]), installation_id)
                self._conn.execute(
                    "INSERT INTO device_session_owners(session_id,installation_id,claimed_at) VALUES(?,?,?)",
                    (session_id, installation_id, now),
                )
                return True
        except sqlite3.Error:
            return False

    def owns_session(self, installation_id: str, session_id: str) -> bool:
        """Return whether an active device owns one session; registry failures deny access."""
        if not self._valid_session_id(session_id):
            return False
        now = float(self._now())
        try:
            with self._lock:
                row = self._conn.execute(
                    """SELECT owner.installation_id
                         FROM device_session_owners AS owner
                         JOIN device_credentials AS credential
                           ON credential.installation_id=owner.installation_id
                        WHERE owner.session_id=? AND owner.installation_id=?
                          AND credential.revoked_at IS NULL AND credential.expires_at > ?""",
                    (session_id, installation_id, now),
                ).fetchone()
        except sqlite3.Error:
            return False
        return row is not None and hmac.compare_digest(str(row[0]), installation_id)
