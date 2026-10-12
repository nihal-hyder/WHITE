"""Server-side sessions. The browser only receives a random opaque token in an HttpOnly cookie.

Supabase access/refresh tokens are kept server-side, encrypted with a key derived from
WHITE_SECRET_KEY, and never exposed to browser JavaScript.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from white.auth.supabase_auth import AuthSession
from white.database.sqlite import SQLiteDatabase

ABSOLUTE_LIFETIME = 7 * 24 * 3600
IDLE_TIMEOUT = 2 * 24 * 3600
RECOVERY_LIFETIME = 15 * 60


@dataclass
class SessionData:
    id_hash: str
    user_id: str
    email: str
    access_token: str
    refresh_token: str
    access_expires_at: int
    created_at: int
    purpose: str  # 'login' or 'recovery'


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionStore:
    def __init__(self, db: SQLiteDatabase, secret: str) -> None:
        self.db = db
        key = base64.urlsafe_b64encode(hashlib.sha256(("white-session:" + secret).encode()).digest())
        self._fernet = Fernet(key)

    def create(self, auth: AuthSession, purpose: str = "login") -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        blob = self._fernet.encrypt(
            json.dumps({"a": auth.access_token, "r": auth.refresh_token}).encode()
        ).decode()
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO sessions (id_hash, user_id, email, token_blob, access_expires_at, created_at,"
                " last_seen_at, purpose) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (_hash(token), auth.user_id, auth.email, blob, auth.expires_at, now, now, purpose),
            )
        return token

    def get(self, token: str | None) -> SessionData | None:
        if not token or len(token) > 200:
            return None
        return self.get_by_hash(_hash(token))

    def get_by_hash(self, id_hash: str) -> SessionData | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id_hash = ?", (id_hash,)).fetchone()
        if row is None:
            return None
        now = int(time.time())
        lifetime = RECOVERY_LIFETIME if row["purpose"] == "recovery" else ABSOLUTE_LIFETIME
        if now - row["created_at"] > lifetime or now - row["last_seen_at"] > IDLE_TIMEOUT:
            self.delete_hash(id_hash)
            return None
        try:
            tokens = json.loads(self._fernet.decrypt(row["token_blob"].encode()))
        except (InvalidToken, ValueError):
            # Secret key changed: the stored tokens cannot be used.
            self.delete_hash(id_hash)
            return None
        if now - row["last_seen_at"] > 60:
            with self.db.connect() as conn:
                conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?", (now, id_hash))
        return SessionData(
            id_hash=id_hash,
            user_id=row["user_id"],
            email=row["email"],
            access_token=tokens["a"],
            refresh_token=tokens["r"],
            access_expires_at=row["access_expires_at"],
            created_at=row["created_at"],
            purpose=row["purpose"],
        )

    def update_tokens(self, id_hash: str, auth: AuthSession) -> None:
        blob = self._fernet.encrypt(
            json.dumps({"a": auth.access_token, "r": auth.refresh_token}).encode()
        ).decode()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE sessions SET token_blob = ?, access_expires_at = ?, email = ? WHERE id_hash = ?",
                (blob, auth.expires_at, auth.email, id_hash),
            )

    def delete(self, token: str | None) -> None:
        if token:
            self.delete_hash(_hash(token))

    def delete_hash(self, id_hash: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE id_hash = ?", (id_hash,))

    def delete_user_sessions(self, user_id: str) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def purge_expired(self) -> None:
        now = int(time.time())
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM sessions WHERE (? - created_at) > ? OR (? - last_seen_at) > ?"
                " OR (purpose = 'recovery' AND (? - created_at) > ?)",
                (now, ABSOLUTE_LIFETIME, now, IDLE_TIMEOUT, now, RECOVERY_LIFETIME),
            )
