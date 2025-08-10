"""User API models"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, field_validator
from uuid import UUID
import re


class UserCreateRequest(BaseModel):
    """Request model for creating a user"""
    
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, max_length=100, description="Password")
    full_name: Optional[str] = Field(None, max_length=100, description="Full name")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$', v):
            raise ValueError(
                "Username must start and end with alphanumeric characters "
                "and can only contain letters, numbers, hyphens, and underscores"
            )
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserUpdateRequest(BaseModel):
    """Request model for updating a user"""
    
    email: Optional[EmailStr] = Field(None, description="Email address")
    full_name: Optional[str] = Field(None, max_length=100, description="Full name")
    bio: Optional[str] = Field(None, max_length=500, description="User bio")
    location: Optional[str] = Field(None, max_length=100, description="Location")
    website: Optional[str] = Field(None, max_length=200, description="Website URL")
    company: Optional[str] = Field(None, max_length=100, description="Company")


class UserResponse(BaseModel):
    """Response model for user"""
    
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    bio: Optional[str] = Field(None, description="User bio")
    location: Optional[str] = Field(None, description="Location")
    website: Optional[str] = Field(None, description="Website URL")
    company: Optional[str] = Field(None, description="Company")
    is_active: bool = Field(True, description="Whether user is active")
    is_admin: bool = Field(False, description="Whether user is admin")
    namespace_count: int = Field(0, description="Number of namespaces owned")
    repository_count: int = Field(0, description="Number of repositories owned")
    created_at: datetime = Field(..., description="Registration timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    
    class Config:
        from_attributes = True


class UserFilterParams(BaseModel):
    """Filter parameters for user list"""
    
    search: Optional[str] = Field(None, description="Search in username, email, and full name")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    is_admin: Optional[bool] = Field(None, description="Filter by admin status")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date")
    
    
class PasswordChangeRequest(BaseModel):
    """Request model for changing password"""
    
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', v):
            raise ValueError("Password must contain at least one digit")
        return v
    
    
class UserPublicResponse(BaseModel):
    """Public response model for user (limited information)"""
    
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    full_name: Optional[str] = Field(None, description="Full name")
    bio: Optional[str] = Field(None, description="User bio")
    location: Optional[str] = Field(None, description="Location")
    website: Optional[str] = Field(None, description="Website URL")
    company: Optional[str] = Field(None, description="Company")
    namespace_count: int = Field(0, description="Number of public namespaces")
    repository_count: int = Field(0, description="Number of public repositories")
    created_at: datetime = Field(..., description="Registration timestamp")