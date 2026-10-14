"""Application configuration loaded from environment variables and an optional .env file.

The scanner itself only needs :class:`white.scanner.models.ScanConfig`; this module adds the
settings used by the web application (sessions, Supabase, persistence).
"""

from __future__ import annotations

import secrets
import tempfile
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from white.scanner.models import ScanConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Supabase (optional). Only the public URL and publishable/anon key are used. ---
    supabase_url: str | None = Field(default=None, validation_alias="SUPABASE_URL")
    supabase_publishable_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SUPABASE_PUBLISHABLE_KEY", "SUPABASE_ANON_KEY"),
    )

    # --- Web application ---
    secret_key: str | None = Field(default=None, validation_alias="WHITE_SECRET_KEY")
    site_url: str = Field(default="", validation_alias="WHITE_SITE_URL")
    data_dir: Path = Field(default=Path.home() / ".white", validation_alias="WHITE_DATA_DIR")
    cookie_secure: bool | None = Field(default=None, validation_alias="WHITE_COOKIE_SECURE")
    require_domain_verification: bool | None = Field(
        default=None, validation_alias="WHITE_REQUIRE_DOMAIN_VERIFICATION"
    )
    max_concurrent_scans: int = Field(default=3, ge=1, le=20, validation_alias="WHITE_MAX_CONCURRENT_SCANS")
    scans_per_user_per_hour: int = Field(
        default=20, ge=1, le=500, validation_alias="WHITE_SCANS_PER_USER_PER_HOUR"
    )

    # --- Hosting ---
    # Serverless mode (auto-enabled on Vercel): no local disk state, scans run inside the request,
    # sessions live in encrypted cookies and domain verifications in Supabase.
    serverless: bool | None = Field(default=None, validation_alias="WHITE_SERVERLESS")
    trust_proxy_headers: bool | None = Field(default=None, validation_alias="WHITE_TRUST_PROXY_HEADERS")
    vercel: str | None = Field(default=None, validation_alias="VERCEL")
    vercel_url: str | None = Field(default=None, validation_alias="VERCEL_URL")
    vercel_branch_url: str | None = Field(default=None, validation_alias="VERCEL_BRANCH_URL")
    vercel_production_url: str | None = Field(default=None, validation_alias="VERCEL_PROJECT_PRODUCTION_URL")

    # --- Operator admin console (separate from per-user accounts) ---
    admin_user: str = Field(default="nihal", validation_alias="WHITE_ADMIN_USER")
    admin_password: str = Field(default="nihal", validation_alias="WHITE_ADMIN_PASSWORD")
    admin_password_hash: str | None = Field(default=None, validation_alias="WHITE_ADMIN_PASSWORD_HASH")
    admin_enabled_opt: bool | None = Field(default=None, validation_alias="WHITE_ADMIN_ENABLED")
    # Optional Supabase service-role key: ONLY used server-side by the admin console to list all
    # registered users and their scans. Never sent to the browser, never required.
    supabase_service_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("WHITE_SUPABASE_SERVICE_KEY", "SUPABASE_SERVICE_ROLE_KEY"),
    )

    # --- Scanner safety limits ---
    allow_private_targets: bool = Field(default=False, validation_alias="WHITE_ALLOW_PRIVATE_TARGETS")
    request_timeout: float = Field(default=10.0, gt=0, le=60, validation_alias="WHITE_REQUEST_TIMEOUT")
    max_scan_seconds: float = Field(default=120.0, gt=0, le=900, validation_alias="WHITE_MAX_SCAN_SECONDS")
    max_response_bytes: int = Field(
        default=2_000_000, ge=10_000, le=20_000_000, validation_alias="WHITE_MAX_RESPONSE_BYTES"
    )

    @field_validator(
        "supabase_url",
        "supabase_publishable_key",
        "secret_key",
        "admin_password_hash",
        "supabase_service_key",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value.strip() if isinstance(value, str) else value

    @field_validator("supabase_url")
    @classmethod
    def _validate_supabase_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("https://"):
            raise ValueError("SUPABASE_URL must start with https://")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _derive_hosting(self) -> Settings:
        if not self.site_url:
            if self.vercel_production_url:
                self.site_url = f"https://{self.vercel_production_url}"
            elif self.vercel_url:
                self.site_url = f"https://{self.vercel_url}"
            else:
                self.site_url = "http://127.0.0.1:8000"
        self.site_url = self.site_url.rstrip("/")
        if (
            self.is_serverless
            and "WHITE_DATA_DIR" not in self.model_fields_set
            and "data_dir" not in self.model_fields_set
        ):
            self.data_dir = Path(tempfile.gettempdir()) / "white"  # writable scratch only; no durable state
        return self

    @property
    def is_serverless(self) -> bool:
        if self.serverless is not None:
            return self.serverless
        return self.vercel == "1"

    @property
    def proxy_headers_trusted(self) -> bool:
        if self.trust_proxy_headers is not None:
            return self.trust_proxy_headers
        return self.vercel == "1"

    @property
    def execution_mode(self) -> str:
        """'background' (in-process worker threads) or 'inline' (scan runs inside a request)."""
        return "inline" if self.is_serverless else "background"

    @property
    def deployment_hosts(self) -> list[str]:
        return [h for h in (self.vercel_url, self.vercel_branch_url, self.vercel_production_url) if h]

    def configuration_problems(self) -> list[str]:
        """Settings that make a hosted (serverless) deployment unsafe or unusable."""
        problems = []
        if self.is_serverless:
            if not self.supabase_enabled:
                problems.append(
                    "SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be set: a hosted WHITE "
                    "requires accounts so it can never act as an open scanner."
                )
            if not self.secret_key or len(self.secret_key) < 32:
                problems.append("WHITE_SECRET_KEY must be set to a random value of at least 32 characters.")
            if self.allow_private_targets:
                problems.append("WHITE_ALLOW_PRIVATE_TARGETS must not be enabled on a hosted deployment.")
        return problems

    @property
    def supabase_enabled(self) -> bool:
        return bool(self.supabase_url and self.supabase_publishable_key)

    @property
    def auth_mode(self) -> str:
        return "supabase" if self.supabase_enabled else "local"

    @property
    def domain_verification_required(self) -> bool:
        if self.is_serverless:
            return True  # never optional on a publicly hosted deployment
        if self.require_domain_verification is not None:
            return self.require_domain_verification
        # Multi-user (hosted) mode requires proof of ownership by default.
        return self.supabase_enabled

    @property
    def admin_enabled(self) -> bool:
        """Whether the /admin operator console is reachable."""
        if self.admin_enabled_opt is not None:
            return self.admin_enabled_opt
        # On a public (serverless) deployment, only enable it when a real password hash is set,
        # so the weak default credentials are never exposed to the internet.
        if self.is_serverless:
            return bool(self.admin_password_hash)
        return True

    @property
    def admin_uses_default_password(self) -> bool:
        return self.admin_password_hash is None

    @property
    def admin_cross_user(self) -> bool:
        """Whether the admin console can list all registered users and their scans (Supabase)."""
        return bool(self.supabase_enabled and self.supabase_service_key)

    @property
    def secure_cookies(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.site_url.startswith("https://")

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / "white.db"

    def effective_secret_key(self) -> str:
        """Return the configured secret, or an ephemeral one (sessions reset on restart)."""
        if self.secret_key:
            return self.secret_key
        if not hasattr(self, "_ephemeral_secret"):
            object.__setattr__(self, "_ephemeral_secret", secrets.token_urlsafe(48))
        return self._ephemeral_secret  # type: ignore[attr-defined]

    def scan_config(self, *, active_checks: bool = False) -> ScanConfig:
        return ScanConfig(
            allow_private_targets=self.allow_private_targets,
            request_timeout=self.request_timeout,
            max_scan_seconds=self.max_scan_seconds,
            max_response_bytes=self.max_response_bytes,
            active_checks=active_checks,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
