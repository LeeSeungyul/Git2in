"""Repository API models"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from uuid import UUID
import re


class RepositoryCreateRequest(BaseModel):
    """Request model for creating a repository"""
    
    name: str = Field(..., min_length=1, max_length=100, description="Repository name")
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    visibility: str = Field("private", pattern="^(public|private)$", description="Visibility")
    default_branch: str = Field("main", description="Default branch name")
    init_readme: bool = Field(False, description="Initialize with README")
    gitignore_template: Optional[str] = Field(None, description="Gitignore template name")
    license_template: Optional[str] = Field(None, description="License template name")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate repository name format"""
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$', v):
            raise ValueError(
                "Repository name must start and end with alphanumeric characters "
                "and can only contain letters, numbers, hyphens, underscores, and dots"
            )
        if len(v) < 2:
            raise ValueError("Repository name must be at least 2 characters long")
        return v


class RepositoryUpdateRequest(BaseModel):
    """Request model for updating a repository"""
    
    description: Optional[str] = Field(None, max_length=1000, description="Description")
    visibility: Optional[str] = Field(None, pattern="^(public|private)$", description="Visibility")
    default_branch: Optional[str] = Field(None, description="Default branch name")
    archived: Optional[bool] = Field(None, description="Archive status")


class RepositoryResponse(BaseModel):
    """Response model for repository"""
    
    id: UUID = Field(..., description="Repository ID")
    namespace_id: UUID = Field(..., description="Namespace ID")
    namespace_name: str = Field(..., description="Namespace name")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full repository name (namespace/repo)")
    description: Optional[str] = Field(None, description="Description")
    visibility: str = Field(..., description="Visibility")
    default_branch: str = Field(..., description="Default branch")
    size_bytes: int = Field(0, description="Repository size in bytes")
    star_count: int = Field(0, description="Number of stars")
    fork_count: int = Field(0, description="Number of forks")
    archived: bool = Field(False, description="Whether repository is archived")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    last_push_at: Optional[datetime] = Field(None, description="Last push timestamp")
    clone_url_http: str = Field(..., description="HTTP clone URL")
    clone_url_ssh: Optional[str] = Field(None, description="SSH clone URL")
    
    class Config:
        from_attributes = True


class RepositoryFilterParams(BaseModel):
    """Filter parameters for repository list"""
    
    search: Optional[str] = Field(None, description="Search in name and description")
    visibility: Optional[str] = Field(None, pattern="^(public|private)$", description="Filter by visibility")
    archived: Optional[bool] = Field(None, description="Filter by archive status")
    language: Optional[str] = Field(None, description="Filter by primary language")
    
    
class RepositoryStatsResponse(BaseModel):
    """Response model for repository statistics"""
    
    commits: int = Field(0, description="Total number of commits")
    branches: int = Field(0, description="Number of branches")
    tags: int = Field(0, description="Number of tags")
    contributors: int = Field(0, description="Number of contributors")
    open_issues: int = Field(0, description="Number of open issues")
    open_pull_requests: int = Field(0, description="Number of open pull requests")
    languages: Dict[str, int] = Field(default_factory=dict, description="Language statistics (bytes)")
    
    
class RepositoryCollaboratorRequest(BaseModel):
    """Request model for adding repository collaborator"""
    
    user_id: UUID = Field(..., description="User ID to add")
    permission: str = Field("read", pattern="^(read|write|admin)$", description="Permission level")
    
    
class RepositoryCollaboratorResponse(BaseModel):
    """Response model for repository collaborator"""
    
    user_id: UUID = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="User email")
    permission: str = Field(..., description="Permission level")
    added_at: datetime = Field(..., description="When collaborator was added")