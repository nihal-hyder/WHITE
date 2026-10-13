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
from contextvars import ContextVar
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


# ----------------------------------------------------------------------------- serverless sessions
# A request-scoped holder lets the session store hand a refreshed cookie value to the middleware,
# which writes it on the response. Context variables are copied into FastAPI's worker threads,
# but the holder dict is shared by reference, so updates made in an endpoint are visible here.
PENDING_SESSION_COOKIE: ContextVar[dict | None] = ContextVar("white_pending_session_cookie", default=None)
COOKIE_MAX_BYTES = 3800


class CookieSessionStore:
    """Stateless sessions for serverless hosting: the encrypted session lives in the cookie.

    The cookie is encrypted and authenticated with a key derived from WHITE_SECRET_KEY (Fernet),
    so it cannot be read or forged by the browser. Because nothing is stored server-side,
    revocation relies on Supabase: signing out revokes the Supabase session, and every request
    re-validates the access token with Supabase Auth (see ``Services.session_still_valid``).
    """

    stateless = True

    def __init__(self, secret: str) -> None:
        key = base64.urlsafe_b64encode(hashlib.sha256(("white-cookie-session:" + secret).encode()).digest())
        self._fernet = Fernet(key)
        self._recent: dict[str, str] = {}

    def _encode(self, data: dict) -> str:
        token = self._fernet.encrypt(json.dumps(data, separators=(",", ":")).encode()).decode()
        if len(token) > COOKIE_MAX_BYTES:
            raise ValueError("session cookie too large")
        return token

    def _remember(self, token: str) -> str:
        id_hash = _hash(token)
        if len(self._recent) > 2000:
            self._recent.clear()
        self._recent[id_hash] = token
        return id_hash

    def create(self, auth: AuthSession, purpose: str = "login") -> str:
        now = int(time.time())
        return self._encode(
            {
                "u": auth.user_id,
                "e": auth.email,
                "a": auth.access_token,
                "r": auth.refresh_token,
                "x": auth.expires_at,
                "c": now,
                "p": purpose,
            }
        )

    def get(self, token: str | None) -> SessionData | None:
        if not token or len(token) > COOKIE_MAX_BYTES:
            return None
        try:
            raw = self._fernet.decrypt(token.encode())
            data = json.loads(raw)
        except (InvalidToken, ValueError):
            return None
        lifetime = RECOVERY_LIFETIME if data.get("p") == "recovery" else ABSOLUTE_LIFETIME
        if int(time.time()) - int(data.get("c", 0)) > lifetime:
            return None
        return SessionData(
            id_hash=self._remember(token),
            user_id=data["u"],
            email=data["e"],
            access_token=data["a"],
            refresh_token=data["r"],
            access_expires_at=int(data["x"]),
            created_at=int(data["c"]),
            purpose=data.get("p", "login"),
        )

    def get_by_hash(self, id_hash: str) -> SessionData | None:
        token = self._recent.get(id_hash)
        return self.get(token) if token else None

    def update_tokens(self, id_hash: str, auth: AuthSession) -> None:
        current = self.get_by_hash(id_hash)
        if current is None:
            return
        token = self._encode(
            {
                "u": auth.user_id,
                "e": auth.email,
                "a": auth.access_token,
                "r": auth.refresh_token,
                "x": auth.expires_at,
                "c": current.created_at,
                "p": current.purpose,
            }
        )
        self._recent[id_hash] = token  # later lookups in this request see the new tokens
        holder = PENDING_SESSION_COOKIE.get()
        if holder is not None:
            holder["value"] = token

    def delete(self, token: str | None) -> None:
        """Nothing is stored server-side; the route clears the cookie and Supabase revokes."""

    def delete_hash(self, id_hash: str) -> None:
        self._recent.pop(id_hash, None)
        holder = PENDING_SESSION_COOKIE.get()
        if holder is not None:
            holder["clear"] = True

    def delete_user_sessions(self, user_id: str) -> None:
        """Global revocation is performed by Supabase (sign-out with scope=global)."""

    def purge_expired(self) -> None:
        """Nothing to purge."""
