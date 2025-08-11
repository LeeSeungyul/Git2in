import re
from datetime import datetime
from typing import ClassVar, List, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class User(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True, json_encoders={datetime: lambda v: v.isoformat()}
    )

    id: UUID = Field(default_factory=uuid4, description="Unique user identifier")
    username: str = Field(
        ..., min_length=3, max_length=32, description="Unique username"
    )
    email: Optional[EmailStr] = Field(None, description="User email address")
    full_name: Optional[str] = Field(
        None, max_length=128, description="User's full name"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Account creation timestamp"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Last update timestamp"
    )
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    is_active: bool = Field(
        default=True, description="Whether the user account is active"
    )
    is_admin: bool = Field(
        default=False, description="Whether the user has admin privileges"
    )
    permissions: List[str] = Field(
        default_factory=list, description="List of user permissions"
    )

    # Username validation pattern
    USERNAME_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$"
    )

    # Reserved usernames
    RESERVED_USERNAMES: ClassVar[Set[str]] = {
        "admin",
        "root",
        "system",
        "api",
        "git",
        "anonymous",
        "guest",
        "user",
        "test",
        "bot",
        "webhook",
    }

    # Valid permission strings
    VALID_PERMISSIONS: ClassVar[Set[str]] = {
        "namespace:create",
        "namespace:read",
        "namespace:update",
        "namespace:delete",
        "repository:create",
        "repository:read",
        "repository:write",
        "repository:delete",
        "repository:admin",
        "token:create",
        "token:revoke",
        "user:manage",
        "audit:read",
        "admin:all",
    }

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v_lower = v.lower()

        if v_lower in cls.RESERVED_USERNAMES:
            raise ValueError(f"'{v}' is a reserved username")

        if not cls.USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must start and end with alphanumeric characters, "
                "and can contain letters, numbers, underscores, and hyphens"
            )

        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: List[str]) -> List[str]:
        # Remove duplicates
        v = list(set(v))

        # If user has admin:all, they have all permissions
        if "admin:all" in v:
            return ["admin:all"]

        # Validate each permission
        invalid_perms = set(v) - cls.VALID_PERMISSIONS
        if invalid_perms:
            raise ValueError(f"Invalid permissions: {invalid_perms}")

        return sorted(v)

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        if self.is_admin or "admin:all" in self.permissions:
            return True
        return permission in self.permissions

    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if user has any of the specified permissions"""
        if self.is_admin or "admin:all" in self.permissions:
            return True
        return any(p in self.permissions for p in permissions)

    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if user has all of the specified permissions"""
        if self.is_admin or "admin:all" in self.permissions:
            return True
        return all(p in self.permissions for p in permissions)

    def to_dict(self, exclude_sensitive: bool = True) -> dict:
        """Convert model to dictionary for serialization"""
        exclude_fields = set()
        if exclude_sensitive:
            exclude_fields = {"permissions", "is_admin"}
        return self.model_dump(mode="json", exclude=exclude_fields)

    def __str__(self) -> str:
        return f"User({self.username})"

    def __repr__(self) -> str:
        return f"<User id='{self.id}' username='{self.username}'>"
