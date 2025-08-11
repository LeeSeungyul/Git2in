import os
from pathlib import Path
from typing import Literal, Optional

from pydantic import DirectoryPath, Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    app_name: str = Field(default="Git2in", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    environment: Literal["development", "staging", "production"] = Field(
        default="development", description="Environment mode"
    )

    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    api_prefix: str = Field(default="/api/v1", description="API prefix")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO", description="Logging level"
    )
    log_format: Literal["json", "console"] = Field(
        default="console", description="Log output format"
    )

    repository_base_path: Path = Field(
        default=Path("./repositories"), description="Base path for Git repositories"
    )

    # Authentication settings
    signing_key: str = Field(
        default="",
        description="Base64-encoded signing key for tokens (auto-generated if empty)",
    )
    access_token_ttl: int = Field(
        default=3600, description="Access token TTL in seconds (default: 1 hour)"
    )
    refresh_token_ttl: int = Field(
        default=604800, description="Refresh token TTL in seconds (default: 7 days)"
    )
    api_key_ttl: int = Field(
        default=31536000, description="API key TTL in seconds (default: 1 year)"
    )
    key_rotation_days: int = Field(
        default=30, description="Days between signing key rotations"
    )
    key_overlap_days: int = Field(
        default=7, description="Days to keep old keys for verification"
    )

    cors_allow_origins: list[str] = Field(
        default=["*"], description="Allowed CORS origins"
    )
    cors_allow_credentials: bool = Field(
        default=True, description="Allow CORS credentials"
    )

    max_upload_size_mb: int = Field(
        default=100, description="Maximum upload size in megabytes"
    )
    request_timeout_seconds: int = Field(
        default=30, description="Request timeout in seconds"
    )

    git_binary_path: str = Field(default="git", description="Path to git binary")
    git_http_backend_path: str = Field(
        default="git-http-backend", description="Path to git-http-backend binary"
    )

    enable_metrics: bool = Field(default=True, description="Enable Prometheus metrics")
    enable_audit_log: bool = Field(default=True, description="Enable audit logging")

    # Observability settings
    metrics_enabled: bool = Field(default=True, description="Enable metrics endpoint")
    metrics_allowed_ips: list[str] = Field(
        default=["127.0.0.1", "::1"],
        description="IPs allowed to access metrics endpoint",
    )
    metrics_token: Optional[str] = Field(
        default=None, description="Optional token for metrics access"
    )

    @validator("repository_base_path", pre=True)
    def validate_repository_path(cls, v):
        path = Path(v)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        return path

    @validator("log_format", pre=True)
    def validate_log_format(cls, v, values):
        if "environment" in values:
            if values["environment"] == "production":
                return "json"
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


settings = get_settings()
