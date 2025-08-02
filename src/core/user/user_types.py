"""User-related type definitions for Git2in"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from src.core.errors import Git2inError


@dataclass
class UserData:
    """Data required to create a user"""
    username: str
    email: str
    password_hash: str
    is_admin: bool = False


@dataclass
class CreatedUser:
    """Result of user creation"""
    id: UUID
    username: str
    email: str
    created_at: datetime


@dataclass
class ValidationResult:
    """Result of validation check"""
    is_valid: bool
    errors: List[str]


@dataclass
class SSHKeyInfo:
    """Parsed SSH key information"""
    key_type: str
    key_data: str
    comment: Optional[str]
    fingerprint: str


class UserError(Git2inError):
    """Base class for user-related errors"""
    pass


class UserAlreadyExistsError(UserError):
    """Raised when trying to create a user that already exists"""
    def __init__(self, field: str, value: str):
        super().__init__(
            f"User with {field} '{value}' already exists",
            {"field": field, "value": value}
        )


class InvalidUserDataError(UserError):
    """Raised when user data is invalid"""
    def __init__(self, errors: List[str]):
        super().__init__(
            f"Invalid user data: {', '.join(errors)}",
            {"errors": errors}
        )