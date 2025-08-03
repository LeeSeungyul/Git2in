"""Repository management request/response models."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator

from src.api.models.common_models import BaseFilter, PaginationParams


class RepositoryOwner(BaseModel):
    """Repository owner information."""
    id: UUID = Field(..., description="Owner user ID")
    username: str = Field(..., description="Owner username")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "johndoe"
            }
        }


class CloneUrls(BaseModel):
    """Repository clone URLs."""
    http: str = Field(..., description="HTTP clone URL")
    ssh: str = Field(..., description="SSH clone URL")
    
    class Config:
        json_schema_extra = {
            "example": {
                "http": "https://git2in.example.com/johndoe/my-awesome-project.git",
                "ssh": "git@git2in.example.com:johndoe/my-awesome-project.git"
            }
        }


class CreateRepositoryRequest(BaseModel):
    """Create repository request model."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern="^[a-zA-Z0-9_.-]+$",
        description="Repository name (alphanumeric, underscore, dash, dot)"
    )
    description: Optional[str] = Field(None, max_length=500, description="Repository description")
    private: bool = Field(False, description="Whether the repository is private")
    default_branch: Optional[str] = Field("main", description="Default branch name")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate repository name."""
        if v.startswith('.') or v.endswith('.'):
            raise ValueError('Repository name cannot start or end with a dot')
        if '..' in v:
            raise ValueError('Repository name cannot contain consecutive dots')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "my-awesome-project",
                "description": "A cool project",
                "private": False,
                "default_branch": "main"
            }
        }


class RepositoryResponse(BaseModel):
    """Repository response model."""
    id: UUID = Field(..., description="Repository ID")
    name: str = Field(..., description="Repository name")
    description: Optional[str] = Field(None, description="Repository description")
    private: bool = Field(..., description="Whether the repository is private")
    owner: RepositoryOwner = Field(..., description="Repository owner")
    clone_urls: CloneUrls = Field(..., description="Clone URLs")
    default_branch: str = Field(..., description="Default branch")
    size_kb: int = Field(0, description="Repository size in kilobytes")
    last_push_at: Optional[datetime] = Field(None, description="Last push timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    @classmethod
    def from_dto(cls, repo_dto) -> "RepositoryResponse":
        """Create from RepositoryDTO."""
        return cls(
            id=repo_dto.id,
            name=repo_dto.name,
            description=repo_dto.description,
            private=repo_dto.is_private,
            owner=RepositoryOwner(
                id=repo_dto.owner.id,
                username=repo_dto.owner.username
            ),
            clone_urls=CloneUrls(
                http=repo_dto.clone_urls.http,
                ssh=repo_dto.clone_urls.ssh
            ),
            default_branch=repo_dto.default_branch,
            size_kb=repo_dto.size_bytes // 1024,
            last_push_at=repo_dto.last_push_at,
            created_at=repo_dto.created_at,
            updated_at=repo_dto.updated_at
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "my-awesome-project",
                "description": "A cool project",
                "private": False,
                "owner": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "johndoe"
                },
                "clone_urls": {
                    "http": "https://git2in.example.com/johndoe/my-awesome-project.git",
                    "ssh": "git@git2in.example.com:johndoe/my-awesome-project.git"
                },
                "default_branch": "main",
                "size_kb": 1024,
                "last_push_at": "2024-01-19T15:20:00Z",
                "created_at": "2024-01-20T10:30:00Z",
                "updated_at": "2024-01-20T10:30:00Z"
            }
        }


class RepositoryListItem(BaseModel):
    """Repository item in list response."""
    id: UUID = Field(..., description="Repository ID")
    name: str = Field(..., description="Repository name")
    description: Optional[str] = Field(None, description="Repository description")
    private: bool = Field(..., description="Whether the repository is private")
    owner: RepositoryOwner = Field(..., description="Repository owner")
    last_push_at: Optional[datetime] = Field(None, description="Last push timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")
    
    @classmethod
    def from_dto(cls, repo_dto) -> "RepositoryListItem":
        """Create from RepositoryDTO."""
        return cls(
            id=repo_dto.id,
            name=repo_dto.name,
            description=repo_dto.description,
            private=repo_dto.is_private,
            owner=RepositoryOwner(
                id=repo_dto.owner.id,
                username=repo_dto.owner.username
            ),
            last_push_at=repo_dto.last_push_at,
            created_at=repo_dto.created_at
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "my-awesome-project",
                "description": "A cool project",
                "private": False,
                "owner": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "johndoe"
                },
                "last_push_at": "2024-01-19T15:20:00Z",
                "created_at": "2024-01-20T10:30:00Z"
            }
        }


class UpdateRepositoryRequest(BaseModel):
    """Update repository request model."""
    description: Optional[str] = Field(None, max_length=500, description="Repository description")
    private: Optional[bool] = Field(None, description="Whether the repository is private")
    default_branch: Optional[str] = Field(None, description="Default branch name")
    
    class Config:
        json_schema_extra = {
            "example": {
                "description": "An even cooler project",
                "private": True,
                "default_branch": "develop"
            }
        }


class RepositoryFilter(BaseFilter):
    """Repository list filter parameters."""
    owner: Optional[str] = Field(None, description="Filter by owner username")
    private: Optional[bool] = Field(None, description="Filter by visibility")
    search: Optional[str] = Field(None, description="Search in name and description")
    sort: Optional[str] = Field(
        "created_at",
        description="Sort field (name, created_at, updated_at, pushed_at)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "owner": "johndoe",
                "private": False,
                "search": "awesome",
                "sort": "created_at",
                "order": "desc",
                "page": 1,
                "per_page": 20
            }
        }


class CollaboratorPermission(str):
    """Collaborator permission levels."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class AddCollaboratorRequest(BaseModel):
    """Add repository collaborator request."""
    username: str = Field(..., description="Collaborator username")
    permission: CollaboratorPermission = Field(
        CollaboratorPermission.READ,
        description="Permission level"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "janedoe",
                "permission": "write"
            }
        }


class CollaboratorResponse(BaseModel):
    """Repository collaborator response."""
    id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    permission: str = Field(..., description="Permission level")
    added_at: datetime = Field(..., description="When the collaborator was added")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "janedoe",
                "permission": "write",
                "added_at": "2024-01-20T10:30:00Z"
            }
        }