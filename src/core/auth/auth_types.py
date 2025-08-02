"""Auth-related type definitions and exceptions for Git2in"""

from typing import Optional
from src.core.errors import Git2inError


class AuthenticationError(Git2inError):
    """Base class for authentication errors"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""
    def __init__(self):
        super().__init__("Invalid username or password")


class TokenExpiredError(AuthenticationError):
    """Raised when token has expired"""
    def __init__(self):
        super().__init__("Token has expired")


class InvalidTokenError(AuthenticationError):
    """Raised when token is invalid"""
    def __init__(self):
        super().__init__("Invalid token")


class PermissionDeniedError(AuthenticationError):
    """Raised when permission is denied"""
    def __init__(self, action: str, resource: str):
        super().__init__(
            f"Permission denied for {action} on {resource}",
            {"action": action, "resource": resource}
        )


class RateLimitError(AuthenticationError):
    """Raised when rate limit is exceeded"""
    def __init__(self, retry_after: int):
        super().__init__(
            f"Rate limit exceeded. Try again in {retry_after} seconds",
            {"retry_after": retry_after}
        )