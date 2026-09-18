"""Validated configuration. Never render connection URLs with passwords."""

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class ConfigurationError(ValueError):
    """Safe configuration failure for command-line and application startup."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CORE_",
        env_file=None,
        extra="ignore",
        hide_input_in_errors=True,
        frozen=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    service_name: str = Field(default="The Editing Tab Core", min_length=1, max_length=80)
    db_host: str = "127.0.0.1"
    db_port: int = Field(default=15432, ge=1, le=65535)
    db_name: str = Field(default="editingtab_core", pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    db_username: str = Field(default="editingtab_dev", min_length=1, max_length=63)
    db_password: SecretStr = Field(repr=False, exclude=True)
    db_connect_timeout: int = Field(default=3, ge=2, le=10)

    auth_allowed_origins: tuple[str, ...] = ()
    auth_session_seconds: int = Field(default=28800, ge=60, le=604800)
    auth_window_seconds: int = Field(default=300, ge=1, le=3600)
    auth_account_limit: int = Field(default=5, ge=1, le=100)
    auth_source_limit: int = Field(default=30, ge=1, le=1000)

    booking_service_current_digest: SecretStr | None = Field(default=None, repr=False, exclude=True)
    booking_service_previous_digest: SecretStr | None = Field(
        default=None, repr=False, exclude=True
    )

    @field_validator("booking_service_current_digest", "booking_service_previous_digest")
    @classmethod
    def service_digest(cls, value):
        if value is not None and re.fullmatch(r"[0-9a-f]{64}", value.get_secret_value()) is None:
            raise ValueError("Service digest must be lowercase SHA-256 hexadecimal.")
        return value

    @property
    def auth_secure_cookie(self) -> bool:
        # An omitted environment must never silently enable insecure cookies.
        return not (
            self.environment in {"development", "test"} and "environment" in self.model_fields_set
        )

    @model_validator(mode="after")
    def valid_origins(self):
        for origin in self.auth_allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or origin != f"{parsed.scheme}://{parsed.netloc}"
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "*" in origin
                or any(ord(c) <= 32 for c in origin)
                or (self.auth_secure_cookie and parsed.scheme != "https")
            ):
                raise ValueError("Use exact HTTP(S) origins; secure mode requires HTTPS.")
            _ = parsed.port
        return self

    @field_validator("db_host")
    @classmethod
    def single_host(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", value):
                raise ValueError("Use one IP address or hostname") from None
        return value

    @field_validator("service_name", "db_username")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Must be nonblank and contain no control characters")
        return value

    @field_validator("db_password")
    @classmethod
    def usable_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if (
            not password
            or "\x00" in password
            or password == "REPLACE_WITH_GENERATED_LOCAL_PASSWORD"
        ):
            raise ValueError("A nonempty database password is required")
        return value

    def database_url(self) -> URL:
        # URL.create avoids manual quoting/interpolation, including %, @, / and #.
        return URL.create(
            "postgresql+psycopg",
            username=self.db_username,
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


def load_settings(*, env_file: str | None = ".env") -> Settings:
    try:
        return Settings(_env_file=env_file)
    except (ValidationError, ValueError, OSError):
        # Do not propagate raw environment values or credential-bearing exceptions.
        raise ConfigurationError(
            "Invalid CORE_ configuration; check required values and bounds"
        ) from None
