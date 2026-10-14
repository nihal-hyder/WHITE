"""Operator admin authentication: credential check and an encrypted admin session cookie.

This is entirely separate from the per-user Supabase accounts. It gates the `/admin` operator
console. The admin session is a Fernet-encrypted, time-limited token kept in an HttpOnly cookie;
the browser never sees anything meaningful inside it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from cryptography.fernet import Fernet, InvalidToken

from white.auth.passwords import verify_password

ADMIN_COOKIE = "white_admin"
ADMIN_SESSION_LIFETIME = 8 * 3600


class AdminAuth:
    def __init__(self, username: str, password_hash: str, secret: str, *, default_password: bool) -> None:
        self.username = username.strip()
        self._hash = password_hash
        self.default_password = default_password
        key = base64.urlsafe_b64encode(hashlib.sha256(("white-admin:" + secret).encode()).digest())
        self._fernet = Fernet(key)

    def verify(self, username: str, password: str) -> bool:
        user_ok = hmac.compare_digest((username or "").strip().lower(), self.username.lower())
        pw_ok = verify_password(password or "", self._hash)
        return user_ok and pw_ok

    def create_session(self) -> str:
        return self._fernet.encrypt(json.dumps({"a": 1, "t": int(time.time())}).encode()).decode()

    def session_valid(self, token: str | None) -> bool:
        if not token or len(token) > 512:
            return False
        try:
            data = json.loads(self._fernet.decrypt(token.encode(), ttl=ADMIN_SESSION_LIFETIME))
        except (InvalidToken, ValueError):
            return False
        return data.get("a") == 1
