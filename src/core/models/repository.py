import re
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Optional, Set
from uuid import UUID

from pydantic import (BaseModel, ConfigDict, Field, computed_field,
                      field_validator)

from src.core.config import settings


class Repository(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        json_encoders={datetime: lambda v: v.isoformat(), Path: lambda v: str(v)},
    )

    name: str = Field(..., min_length=1, max_length=128, description="Repository name")
    namespace_name: str = Field(..., description="Parent namespace name")
    description: Optional[str] = Field(
        None, max_length=1000, description="Repository description"
    )
    owner_id: UUID = Field(..., description="UUID of the repository owner")
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of repository creation"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of last update"
    )
    is_private: bool = Field(
        default=True, description="Whether the repository is private"
    )
    default_branch: str = Field(default="main", description="Default branch name")
    size_bytes: int = Field(default=0, ge=0, description="Repository size in bytes")
    is_active: bool = Field(
        default=True, description="Whether the repository is active"
    )
    is_archived: bool = Field(
        default=False, description="Whether the repository is archived"
    )

    # Regex pattern for valid repository names
    NAME_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$"
    )

    # Reserved repository names
    RESERVED_NAMES: ClassVar[Set[str]] = {
        ".git",
        ".gitignore",
        "HEAD",
        "config",
        "description",
        "hooks",
        "info",
        "objects",
        "refs",
        "branches",
        "tags",
    }

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if v in cls.RESERVED_NAMES:
            raise ValueError(f"'{v}' is a reserved repository name")

        if not cls.NAME_PATTERN.match(v):
            raise ValueError(
                "Repository name must start and end with alphanumeric characters, "
                "and can contain letters, numbers, dots, underscores, and hyphens"
            )

        if ".." in v:
            raise ValueError("Repository name cannot contain consecutive dots")

        if v.endswith(".git"):
            v = v[:-4]  # Remove .git suffix if provided

        return v

    @field_validator("default_branch")
    @classmethod
    def validate_branch_name(cls, v: str) -> str:
        if not v:
            return "main"

        # Basic branch name validation
        invalid_chars = ["~", "^", ":", "\\", " ", "?", "*", "["]
        for char in invalid_chars:
            if char in v:
                raise ValueError(f"Branch name cannot contain '{char}'")

        return v

    @field_validator("size_bytes")
    @classmethod
    def validate_size(cls, v: int) -> int:
        max_size = getattr(
            settings, "max_repo_size_bytes", 1024 * 1024 * 1024
        )  # Default 1GB
        if v > max_size:
            raise ValueError(
                f"Repository size exceeds maximum allowed size of {max_size} bytes"
            )
        return v

    @computed_field
    @property
    def full_name(self) -> str:
        """Returns the full repository name (namespace/repo)"""
        return f"{self.namespace_name}/{self.name}"

    @computed_field
    @property
    def git_dir_name(self) -> str:
        """Returns the directory name for the bare git repository"""
        return f"{self.name}.git"

    @computed_field
    @property
    def relative_path(self) -> Path:
        """Returns the relative path from repository base"""
        return Path("namespaces") / self.namespace_name / "repos" / self.git_dir_name

    @computed_field
    @property
    def absolute_path(self) -> Path:
        """Returns the absolute filesystem path to the repository"""
        return settings.repository_base_path / self.relative_path

    @computed_field
    @property
    def clone_url_http(self) -> str:
        """Returns the HTTP clone URL for the repository"""
        base_url = getattr(settings, "base_url", "http://localhost:8000")
        return f"{base_url}/git/{self.full_name}.git"

    @computed_field
    @property
    def clone_url_ssh(self) -> str:
        """Returns the SSH clone URL for the repository"""
        ssh_host = getattr(settings, "ssh_host", "localhost")
        return f"git@{ssh_host}:{self.full_name}.git"

    @computed_field
    @property
    def size_mb(self) -> float:
        """Returns the repository size in megabytes"""
        return round(self.size_bytes / (1024 * 1024), 2)

    def to_dict(self) -> dict:
        """Convert model to dictionary for serialization"""
        return self.model_dump(mode="json")

    def __str__(self) -> str:
        return f"Repository({self.full_name})"

    def __repr__(self) -> str:
        return f"<Repository name='{self.full_name}' owner_id='{self.owner_id}'>"
