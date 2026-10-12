"""Thin client for the official Supabase Auth (GoTrue) REST API.

WHITE never stores or hashes passwords itself; Supabase Auth does. Only the public
publishable/anon key is used.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx


class AuthError(Exception):
    """An authentication problem with a message that is safe to show to users."""

    def __init__(self, message: str, code: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class AuthSession:
    access_token: str
    refresh_token: str
    expires_at: int
    user_id: str
    email: str


@dataclass
class SignUpResult:
    session: AuthSession | None  # None when email confirmation is required
    confirmation_required: bool


FRIENDLY = {
    "invalid_credentials": "The email or password is incorrect.",
    "email_not_confirmed": "Please confirm your email address first. Check your inbox for the link.",
    "user_already_exists": "An account with this email already exists. Try signing in or resetting your password.",
    "email_exists": "An account with this email already exists. Try signing in or resetting your password.",
    "weak_password": "The password is too weak. Use at least 8 characters with a mix of letters, numbers and symbols.",
    "over_email_send_rate_limit": "Too many emails were requested. Please wait a few minutes and try again.",
    "over_request_rate_limit": "Too many attempts. Please wait a few minutes and try again.",
    "same_password": "The new password must be different from the current one.",
    "otp_expired": "This link has expired or was already used. Please request a new one.",
    "signup_disabled": "New sign-ups are currently disabled.",
    "email_address_invalid": "The email address is not valid.",
    "validation_failed": "Please check the details you entered.",
    "reauthentication_needed": "For security, please sign out and sign in again before changing your password.",
    "session_not_found": "Your session has ended. Please sign in again.",
    "refresh_token_not_found": "Your session has ended. Please sign in again.",
    "refresh_token_already_used": "Your session has ended. Please sign in again.",
}


class SupabaseAuthClient:
    def __init__(
        self,
        url: str,
        publishable_key: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._base = f"{url}/auth/v1"
        self._key = publishable_key
        self._transport = transport
        self._timeout = timeout

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: Any = None,
        access_token: str | None = None,
    ) -> dict:
        headers = {"apikey": self._key, "Accept": "application/json"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport, trust_env=False) as client:
                response = client.request(
                    method, f"{self._base}/{path}", params=params, json=json, headers=headers
                )
        except httpx.HTTPError as exc:
            raise AuthError("The account service could not be reached. Please try again.") from exc
        if response.status_code >= 400:
            try:
                body = response.json()
            except ValueError:
                body = {}
            code = body.get("error_code") or body.get("code") or body.get("error")
            if isinstance(code, int):
                code = None
            if code == "invalid_grant":
                description = str(body.get("error_description", "")).lower()
                code = "email_not_confirmed" if "not confirmed" in description else "invalid_credentials"
            message = FRIENDLY.get(code or "")
            if message is None:
                message = (
                    "Too many attempts. Please wait and try again."
                    if response.status_code == 429
                    else "The request could not be completed. Please check your details and try again."
                )
            raise AuthError(message, code=code, status=response.status_code)
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise AuthError("Unexpected response from the account service.") from exc
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _session(data: dict) -> AuthSession:
        user = data.get("user") or {}
        if not data.get("access_token") or not data.get("refresh_token") or not user.get("id"):
            raise AuthError("The account service did not return a session.")
        expires_at = int(data.get("expires_at") or (time.time() + int(data.get("expires_in") or 3600)))
        return AuthSession(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=expires_at,
            user_id=user["id"],
            email=user.get("email") or "",
        )

    def sign_up(self, email: str, password: str, redirect_to: str) -> SignUpResult:
        data = self._call(
            "POST", "signup", params={"redirect_to": redirect_to}, json={"email": email, "password": password}
        )
        if data.get("access_token"):
            return SignUpResult(session=self._session(data), confirmation_required=False)
        # With email confirmation enabled, Supabase returns the user without a session. For an
        # existing address it returns an obfuscated user (to prevent account enumeration); we show
        # the same neutral "check your email" message in both cases.
        return SignUpResult(session=None, confirmation_required=True)

    def sign_in(self, email: str, password: str) -> AuthSession:
        return self._session(
            self._call(
                "POST",
                "token",
                params={"grant_type": "password"},
                json={"email": email, "password": password},
            )
        )

    def refresh(self, refresh_token: str) -> AuthSession:
        return self._session(
            self._call(
                "POST", "token", params={"grant_type": "refresh_token"}, json={"refresh_token": refresh_token}
            )
        )

    def get_user(self, access_token: str) -> dict:
        return self._call("GET", "user", access_token=access_token)

    def session_from_tokens(
        self, access_token: str, refresh_token: str, expires_at: int | None
    ) -> AuthSession:
        """Validate tokens received from an email link (implicit flow) by asking Supabase."""
        user = self.get_user(access_token)
        if not user.get("id"):
            raise AuthError("This link is invalid or has expired.")
        return AuthSession(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=int(expires_at or time.time() + 3600),
            user_id=user["id"],
            email=user.get("email") or "",
        )

    def verify_token_hash(self, token_hash: str, kind: str) -> AuthSession:
        if kind not in {"signup", "email", "recovery", "invite", "email_change", "magiclink"}:
            raise AuthError("This link is not valid.")
        return self._session(self._call("POST", "verify", json={"token_hash": token_hash, "type": kind}))

    def sign_out(self, access_token: str, scope: str = "local") -> None:
        try:
            self._call("POST", "logout", params={"scope": scope}, access_token=access_token)
        except AuthError as exc:
            if exc.status not in {401, 403, 404}:
                raise

    def recover(self, email: str, redirect_to: str) -> None:
        self._call("POST", "recover", params={"redirect_to": redirect_to}, json={"email": email})

    def resend_confirmation(self, email: str, redirect_to: str) -> None:
        self._call(
            "POST", "resend", params={"redirect_to": redirect_to}, json={"type": "signup", "email": email}
        )

    def update_password(self, access_token: str, password: str) -> None:
        self._call("PUT", "user", json={"password": password}, access_token=access_token)
