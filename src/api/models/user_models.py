"""User management request/response models."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, EmailStr, validator


class CreateUserRequest(BaseModel):
    """User registration request model."""
    username: str = Field(
        ...,
        min_length=3,
        max_length=32,
        pattern="^[a-zA-Z0-9_-]+$",
        description="Username (alphanumeric, underscore, dash)"
    )
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john@example.com",
                "password": "secretpassword123"
            }
        }


class UserResponse(BaseModel):
    """User response model."""
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: EmailStr = Field(..., description="Email address")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    
    @classmethod
    def from_dto(cls, user_dto) -> "UserResponse":
        """Create from UserDTO."""
        return cls(
            id=user_dto.id,
            username=user_dto.username,
            email=user_dto.email,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "johndoe",
                "email": "john@example.com",
                "created_at": "2024-01-20T10:30:00Z",
                "updated_at": "2024-01-20T10:30:00Z"
            }
        }


class UserProfileResponse(BaseModel):
    """Extended user profile response."""
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: EmailStr = Field(..., description="Email address")
    is_active: bool = Field(..., description="Whether the user is active")
    is_admin: bool = Field(..., description="Whether the user has admin privileges")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    repository_count: int = Field(0, description="Number of repositories owned")
    total_size_bytes: int = Field(0, description="Total size of all repositories in bytes")
    
    @classmethod
    def from_dto(cls, user_dto, stats: Optional[dict] = None) -> "UserProfileResponse":
        """Create from UserDTO with optional statistics."""
        stats = stats or {}
        return cls(
            id=user_dto.id,
            username=user_dto.username,
            email=user_dto.email,
            is_active=user_dto.is_active,
            is_admin=user_dto.is_admin,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at,
            repository_count=stats.get("repository_count", 0),
            total_size_bytes=stats.get("total_size_bytes", 0)
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "johndoe",
                "email": "john@example.com",
                "is_active": True,
                "is_admin": False,
                "created_at": "2024-01-20T10:30:00Z",
                "updated_at": "2024-01-20T10:30:00Z",
                "repository_count": 5,
                "total_size_bytes": 1048576
            }
        }


class UpdateUserRequest(BaseModel):
    """User profile update request."""
    email: Optional[EmailStr] = Field(None, description="New email address")
    password: Optional[str] = Field(None, min_length=8, description="New password")
    current_password: Optional[str] = Field(None, description="Current password (required for password change)")
    
    @validator('current_password')
    def validate_password_change(cls, v, values):
        """Ensure current password is provided when changing password."""
        if 'password' in values and values['password'] and not v:
            raise ValueError('Current password is required when changing password')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "newemail@example.com",
                "password": "newsecretpassword123",
                "current_password": "oldsecretpassword"
            }
        }


class PersonalAccessTokenRequest(BaseModel):
    """Create personal access token request."""
    name: str = Field(..., min_length=1, max_length=100, description="Token name")
    expires_at: Optional[datetime] = Field(None, description="Token expiration date")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "My CI Token",
                "expires_at": "2024-12-31T23:59:59Z"
            }
        }


class PersonalAccessTokenResponse(BaseModel):
    """Personal access token response."""
    id: UUID = Field(..., description="Token ID")
    name: str = Field(..., description="Token name")
    token: Optional[str] = Field(None, description="Token value (only shown on creation)")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")
    
    @classmethod
    def from_dto(cls, pat_dto) -> "PersonalAccessTokenResponse":
        """Create from PersonalAccessTokenDTO."""
        return cls(
            id=pat_dto.id,
            name=pat_dto.name,
            token=pat_dto.token,  # Only present on creation
            last_used_at=pat_dto.last_used_at,
            expires_at=pat_dto.expires_at,
            created_at=pat_dto.created_at
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "My CI Token",
                "token": "git2in_pat_xxxxxxxxxxxxx",
                "last_used_at": None,
                "expires_at": "2024-12-31T23:59:59Z",
                "created_at": "2024-01-20T10:30:00Z"
            }
        }


class PersonalAccessTokenListResponse(BaseModel):
    """List of personal access tokens."""
    tokens: List[PersonalAccessTokenResponse] = Field(..., description="List of tokens")
    total: int = Field(..., description="Total number of tokens")
    
    class Config:
        json_schema_extra = {
            "example": {
                "tokens": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "name": "My CI Token",
                        "last_used_at": "2024-01-19T15:20:00Z",
                        "expires_at": "2024-12-31T23:59:59Z",
                        "created_at": "2024-01-20T10:30:00Z"
                    }
                ],
                "total": 1
            }
        }