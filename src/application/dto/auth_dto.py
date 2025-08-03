"""Authentication-related data transfer objects.

This module defines DTOs for authentication operations including login,
token management, and access control.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID

from src.application.dto.base import BaseDTO, IdentifiableDTO, TimestampedDTO
from src.application.dto.user_dto import UserDTO


@dataclass
class LoginRequest(BaseDTO):
    """Request DTO for user login."""
    username: str  # Can be username or email
    password: str
    remember_me: bool = False


@dataclass
class TokenResponse(BaseDTO):
    """Response DTO for authentication tokens."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 3600  # seconds
    user: Optional[UserDTO] = None


@dataclass
class RefreshTokenRequest(BaseDTO):
    """Request DTO for refreshing access token."""
    refresh_token: str


@dataclass
class TokenPayload(BaseDTO):
    """JWT token payload information."""
    user_id: UUID
    username: str
    token_type: str  # "access" or "refresh"
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    jti: Optional[str] = None  # JWT ID for tracking
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired.
        
        Returns:
            True if token is expired
        """
        from time import time
        return time() > self.exp


@dataclass
class CreatePersonalAccessTokenRequest(BaseDTO):
    """Request DTO for creating personal access token."""
    name: str
    description: Optional[str] = None
    expires_at: Optional[datetime] = None
    scopes: List[str] = None
    
    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []


@dataclass
class PersonalAccessTokenDTO(IdentifiableDTO, TimestampedDTO):
    """Personal access token DTO."""
    name: str
    description: Optional[str]
    user_id: UUID
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    is_active: bool
    scopes: List[str]
    
    # Token is only included when creating a new PAT
    token: Optional[str] = None
    
    @classmethod
    def from_model(cls, model: Any, token: Optional[str] = None) -> "PersonalAccessTokenDTO":
        """Create PersonalAccessTokenDTO from database model.
        
        Args:
            model: PersonalAccessToken database model
            token: The actual token value (only provided on creation)
            
        Returns:
            PersonalAccessTokenDTO instance
        """
        return cls(
            id=model.id,
            name=model.name,
            description=model.description,
            user_id=model.user_id,
            last_used_at=model.last_used_at,
            expires_at=model.expires_at,
            is_active=model.is_active,
            scopes=getattr(model, 'scopes', []),
            created_at=model.created_at,
            updated_at=model.updated_at,
            token=token
        )


@dataclass
class ValidateTokenRequest(BaseDTO):
    """Request DTO for validating a token."""
    token: str
    token_type: str = "access"  # "access", "refresh", or "pat"


@dataclass
class TokenValidationResult(BaseDTO):
    """Result of token validation."""
    is_valid: bool
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    token_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    scopes: List[str] = None
    
    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []


@dataclass
class LogoutRequest(BaseDTO):
    """Request DTO for user logout."""
    access_token: str
    refresh_token: Optional[str] = None
    everywhere: bool = False  # Logout from all devices


@dataclass
class SessionInfo(BaseDTO):
    """Information about an active session."""
    session_id: str
    user_id: UUID
    created_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_current: bool = False