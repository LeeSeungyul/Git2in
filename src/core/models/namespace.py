import re
from datetime import datetime
from typing import Any, ClassVar, Dict, Optional, Set
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Namespace(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True, json_encoders={datetime: lambda v: v.isoformat()}
    )

    name: str = Field(
        ..., min_length=2, max_length=64, description="Unique namespace identifier"
    )
    description: Optional[str] = Field(
        None, max_length=500, description="Optional namespace description"
    )
    owner_id: UUID = Field(..., description="UUID of the namespace owner")
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of namespace creation"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of last update"
    )
    settings: Dict[str, Any] = Field(
        default_factory=dict, description="Namespace-level configuration settings"
    )
    is_active: bool = Field(default=True, description="Whether the namespace is active")

    # Reserved namespaces that cannot be used
    RESERVED_NAMES: ClassVar[Set[str]] = {
        "api",
        "admin",
        "root",
        "system",
        "git",
        "http",
        "https",
        "ssh",
        "login",
        "logout",
        "register",
        "settings",
        "profile",
        "dashboard",
        "metrics",
        "health",
        "status",
        "about",
        "help",
        "docs",
        "documentation",
        "public",
        "private",
        "test",
        "tests",
    }

    # Regex pattern for valid namespace names
    NAME_PATTERN: ClassVar[re.Pattern] = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]$")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.lower()

        if v in cls.RESERVED_NAMES:
            raise ValueError(f"'{v}' is a reserved namespace name")

        if not cls.NAME_PATTERN.match(v):
            raise ValueError(
                "Namespace name must start with a lowercase letter, "
                "contain only lowercase letters, numbers, and hyphens, "
                "and end with a letter or number"
            )

        if "--" in v:
            raise ValueError("Namespace name cannot contain consecutive hyphens")

        return v

    @field_validator("settings")
    @classmethod
    def validate_settings(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        allowed_keys = {
            "max_repo_size_mb",
            "max_repos",
            "allow_public_repos",
            "default_branch_name",
            "require_signed_commits",
            "webhook_url",
        }

        invalid_keys = set(v.keys()) - allowed_keys
        if invalid_keys:
            raise ValueError(f"Invalid settings keys: {invalid_keys}")

        if "max_repo_size_mb" in v:
            if (
                not isinstance(v["max_repo_size_mb"], (int, float))
                or v["max_repo_size_mb"] <= 0
            ):
                raise ValueError("max_repo_size_mb must be a positive number")

        if "max_repos" in v:
            if not isinstance(v["max_repos"], int) or v["max_repos"] <= 0:
                raise ValueError("max_repos must be a positive integer")

        return v

    @property
    def path_safe_name(self) -> str:
        """Returns the namespace name safe for filesystem paths"""
        return self.name.replace("-", "_")

    def to_dict(self) -> dict:
        """Convert model to dictionary for serialization"""
        return self.model_dump(mode="json")

    def __str__(self) -> str:
        return f"Namespace({self.name})"

    def __repr__(self) -> str:
        return f"<Namespace name='{self.name}' owner_id='{self.owner_id}'>"
