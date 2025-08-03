"""User-related data transfer objects.

This module defines DTOs for user-related operations including registration,
authentication, and profile management.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID

from src.application.dto.base import BaseDTO, IdentifiableDTO, TimestampedDTO


@dataclass
class RegisterUserRequest(BaseDTO):
    """Request DTO for user registration."""
    username: str
    email: str
    password: str


@dataclass
class UpdateProfileRequest(BaseDTO):
    """Request DTO for updating user profile."""
    email: Optional[str] = None
    full_name: Optional[str] = None
    bio: Optional[str] = None


@dataclass
class ChangePasswordRequest(BaseDTO):
    """Request DTO for changing user password."""
    current_password: str
    new_password: str


@dataclass
class UserDTO(IdentifiableDTO, TimestampedDTO):
    """User data transfer object.
    
    Represents user information without sensitive data like passwords.
    """
    username: str
    email: str
    is_active: bool
    is_admin: bool
    full_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    last_login_at: Optional[datetime] = None
    
    @classmethod
    def from_model(cls, model: Any) -> "UserDTO":
        """Create UserDTO from database model.
        
        Args:
            model: User database model
            
        Returns:
            UserDTO instance
        """
        return cls(
            id=model.id,
            username=model.username,
            email=model.email,
            is_active=model.is_active,
            is_admin=model.is_admin,
            full_name=getattr(model, 'full_name', None),
            bio=getattr(model, 'bio', None),
            avatar_url=getattr(model, 'avatar_url', None),
            last_login_at=getattr(model, 'last_login_at', None),
            created_at=model.created_at,
            updated_at=model.updated_at
        )


@dataclass
class PublicUserDTO(BaseDTO):
    """Public user information DTO.
    
    Contains only publicly visible user information.
    """
    id: UUID
    username: str
    full_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime = None
    
    @classmethod
    def from_user_dto(cls, user: UserDTO) -> "PublicUserDTO":
        """Create PublicUserDTO from UserDTO.
        
        Args:
            user: Full UserDTO
            
        Returns:
            PublicUserDTO with only public information
        """
        return cls(
            id=user.id,
            username=user.username,
            full_name=user.full_name,
            bio=user.bio,
            avatar_url=user.avatar_url,
            created_at=user.created_at
        )
    
    @classmethod
    def from_model(cls, model: Any) -> "PublicUserDTO":
        """Create PublicUserDTO from database model.
        
        Args:
            model: User database model
            
        Returns:
            PublicUserDTO instance
        """
        return cls(
            id=model.id,
            username=model.username,
            full_name=getattr(model, 'full_name', None),
            bio=getattr(model, 'bio', None),
            avatar_url=getattr(model, 'avatar_url', None),
            created_at=model.created_at
        )


@dataclass
class UserSearchResult(BaseDTO):
    """User search result DTO."""
    users: List[PublicUserDTO]
    total: int
    query: str