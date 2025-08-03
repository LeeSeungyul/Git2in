"""Authentication request/response models."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, EmailStr


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., min_length=1, description="Username or email")
    password: str = Field(..., min_length=1, description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "secretpassword"
            }
        }


class UserInfo(BaseModel):
    """Basic user information in auth responses."""
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: EmailStr = Field(..., description="Email address")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "johndoe",
                "email": "john@example.com"
            }
        }


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiry time in seconds")
    user: UserInfo = Field(..., description="Authenticated user information")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400,
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "johndoe",
                    "email": "john@example.com"
                }
            }
        }


class RefreshTokenRequest(BaseModel):
    """Token refresh request model."""
    refresh_token: str = Field(..., description="Refresh token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class RefreshTokenResponse(BaseModel):
    """Token refresh response model."""
    access_token: str = Field(..., description="New JWT access token")
    refresh_token: Optional[str] = Field(None, description="New refresh token (if rotated)")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiry time in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 86400
            }
        }


class CurrentUserResponse(BaseModel):
    """Current authenticated user information."""
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: EmailStr = Field(..., description="Email address")
    is_active: bool = Field(..., description="Whether the user is active")
    is_admin: bool = Field(..., description="Whether the user has admin privileges")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    @classmethod
    def from_dto(cls, user_dto) -> "CurrentUserResponse":
        """Create from UserDTO."""
        return cls(
            id=user_dto.id,
            username=user_dto.username,
            email=user_dto.email,
            is_active=user_dto.is_active,
            is_admin=user_dto.is_admin,
            created_at=user_dto.created_at,
            updated_at=user_dto.updated_at
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
                "updated_at": "2024-01-20T10:30:00Z"
            }
        }