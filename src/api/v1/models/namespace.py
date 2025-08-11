"""Namespace API models"""

import re
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class NamespaceCreateRequest(BaseModel):
    """Request model for creating a namespace"""

    name: str = Field(..., min_length=1, max_length=100, description="Namespace name")
    display_name: Optional[str] = Field(
        None, max_length=200, description="Display name"
    )
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    visibility: str = Field(
        "private", pattern="^(public|private)$", description="Visibility"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate namespace name format"""
        if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", v):
            raise ValueError(
                "Namespace name must start and end with alphanumeric characters "
                "and can only contain lowercase letters, numbers, and hyphens"
            )
        if len(v) < 3:
            raise ValueError("Namespace name must be at least 3 characters long")
        return v


class NamespaceUpdateRequest(BaseModel):
    """Request model for updating a namespace"""

    display_name: Optional[str] = Field(
        None, max_length=200, description="Display name"
    )
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    visibility: Optional[str] = Field(
        None, pattern="^(public|private)$", description="Visibility"
    )


class NamespaceResponse(BaseModel):
    """Response model for namespace"""

    id: UUID = Field(..., description="Namespace ID")
    name: str = Field(..., description="Namespace name")
    display_name: Optional[str] = Field(None, description="Display name")
    description: Optional[str] = Field(None, description="Description")
    visibility: str = Field(..., description="Visibility")
    owner_id: UUID = Field(..., description="Owner user ID")
    repository_count: int = Field(0, description="Number of repositories")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True


class NamespaceListResponse(BaseModel):
    """Response model for namespace list"""

    namespaces: List[NamespaceResponse] = Field(..., description="List of namespaces")
    total: int = Field(..., description="Total number of namespaces")


class NamespaceFilterParams(BaseModel):
    """Filter parameters for namespace list"""

    search: Optional[str] = Field(None, description="Search in name and description")
    visibility: Optional[str] = Field(
        None, pattern="^(public|private)$", description="Filter by visibility"
    )
    owner_id: Optional[UUID] = Field(None, description="Filter by owner")


class NamespaceMemberRequest(BaseModel):
    """Request model for adding namespace member"""

    user_id: UUID = Field(..., description="User ID to add")
    role: str = Field(
        "member", pattern="^(admin|member|viewer)$", description="Member role"
    )


class NamespaceMemberResponse(BaseModel):
    """Response model for namespace member"""

    user_id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="User email")
    role: str = Field(..., description="Member role")
    added_at: datetime = Field(..., description="When member was added")
    added_by: UUID = Field(..., description="Who added the member")
