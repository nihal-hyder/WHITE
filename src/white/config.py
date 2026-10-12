"""Application configuration loaded from environment variables and an optional .env file.

The scanner itself only needs :class:`white.scanner.models.ScanConfig`; this module adds the
settings used by the web application (sessions, Supabase, persistence).
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
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
    site_url: str = Field(default="http://127.0.0.1:8000", validation_alias="WHITE_SITE_URL")
    data_dir: Path = Field(default=Path.home() / ".white", validation_alias="WHITE_DATA_DIR")
    cookie_secure: bool | None = Field(default=None, validation_alias="WHITE_COOKIE_SECURE")
    require_domain_verification: bool | None = Field(
        default=None, validation_alias="WHITE_REQUIRE_DOMAIN_VERIFICATION"
    )
    max_concurrent_scans: int = Field(default=3, ge=1, le=20, validation_alias="WHITE_MAX_CONCURRENT_SCANS")
    scans_per_user_per_hour: int = Field(
        default=20, ge=1, le=500, validation_alias="WHITE_SCANS_PER_USER_PER_HOUR"
    )

    # --- Scanner safety limits ---
    allow_private_targets: bool = Field(default=False, validation_alias="WHITE_ALLOW_PRIVATE_TARGETS")
    request_timeout: float = Field(default=10.0, gt=0, le=60, validation_alias="WHITE_REQUEST_TIMEOUT")
    max_scan_seconds: float = Field(default=120.0, gt=0, le=900, validation_alias="WHITE_MAX_SCAN_SECONDS")
    max_response_bytes: int = Field(
        default=2_000_000, ge=10_000, le=20_000_000, validation_alias="WHITE_MAX_RESPONSE_BYTES"
    )

    @field_validator("supabase_url", "supabase_publishable_key", "secret_key", mode="before")
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

    @property
    def supabase_enabled(self) -> bool:
        return bool(self.supabase_url and self.supabase_publishable_key)

    @property
    def auth_mode(self) -> str:
        return "supabase" if self.supabase_enabled else "local"

    @property
    def domain_verification_required(self) -> bool:
        if self.require_domain_verification is not None:
            return self.require_domain_verification
        # Multi-user (hosted) mode requires proof of ownership by default.
        return self.supabase_enabled

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
