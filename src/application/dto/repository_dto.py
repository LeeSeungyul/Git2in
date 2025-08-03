"""Repository-related data transfer objects.

This module defines DTOs for repository operations including creation,
management, and Git operations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from src.application.dto.base import BaseDTO, IdentifiableDTO, TimestampedDTO
from src.application.dto.user_dto import PublicUserDTO


class RepositoryVisibility(str, Enum):
    """Repository visibility levels."""
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"


class RepositoryPermission(str, Enum):
    """Repository permission levels."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


@dataclass
class CreateRepositoryRequest(BaseDTO):
    """Request DTO for creating a repository."""
    name: str
    description: Optional[str] = None
    is_private: bool = True
    default_branch: str = "main"
    init_readme: bool = False
    gitignore_template: Optional[str] = None
    license_template: Optional[str] = None


@dataclass
class UpdateRepositoryRequest(BaseDTO):
    """Request DTO for updating repository settings."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_private: Optional[bool] = None
    default_branch: Optional[str] = None
    archived: Optional[bool] = None


@dataclass
class CloneURLs(BaseDTO):
    """Repository clone URLs."""
    http: str
    ssh: str
    
    @classmethod
    def from_repository(cls, base_url: str, owner: str, repo_name: str) -> "CloneURLs":
        """Create clone URLs from repository information.
        
        Args:
            base_url: Base URL of the Git2in instance
            owner: Repository owner username
            repo_name: Repository name
            
        Returns:
            CloneURLs instance
        """
        # Remove protocol from base_url for SSH
        domain = base_url.replace("https://", "").replace("http://", "")
        
        return cls(
            http=f"{base_url}/{owner}/{repo_name}.git",
            ssh=f"git@{domain}:{owner}/{repo_name}.git"
        )


@dataclass
class RepositoryDTO(IdentifiableDTO, TimestampedDTO):
    """Repository data transfer object."""
    name: str
    owner: PublicUserDTO
    description: Optional[str]
    is_private: bool
    is_archived: bool
    default_branch: str
    size_bytes: int
    clone_urls: CloneURLs
    last_push_at: Optional[datetime] = None
    fork_count: int = 0
    star_count: int = 0
    
    @classmethod
    def from_model(cls, model: Any, base_url: str) -> "RepositoryDTO":
        """Create RepositoryDTO from database model.
        
        Args:
            model: Repository database model (must include owner relation)
            base_url: Base URL for generating clone URLs
            
        Returns:
            RepositoryDTO instance
        """
        clone_urls = CloneURLs.from_repository(
            base_url,
            model.owner.username,
            model.name
        )
        
        return cls(
            id=model.id,
            name=model.name,
            owner=PublicUserDTO.from_model(model.owner),
            description=model.description,
            is_private=model.is_private,
            is_archived=getattr(model, 'is_archived', False),
            default_branch=model.default_branch,
            size_bytes=model.size_bytes,
            clone_urls=clone_urls,
            last_push_at=model.last_push_at,
            fork_count=getattr(model, 'fork_count', 0),
            star_count=getattr(model, 'star_count', 0),
            created_at=model.created_at,
            updated_at=model.updated_at
        )


@dataclass
class RepositoryFilter(BaseDTO):
    """Filter parameters for repository queries."""
    owner_id: Optional[UUID] = None
    owner_username: Optional[str] = None
    visibility: Optional[RepositoryVisibility] = None
    is_archived: Optional[bool] = False
    search: Optional[str] = None
    sort_by: str = "updated_at"  # name, created_at, updated_at, size
    sort_order: str = "desc"  # asc, desc


@dataclass
class RepositoryCollaborator(BaseDTO):
    """Repository collaborator information."""
    user: PublicUserDTO
    permission: RepositoryPermission
    added_at: datetime
    added_by: Optional[PublicUserDTO] = None


@dataclass
class AddCollaboratorRequest(BaseDTO):
    """Request DTO for adding repository collaborator."""
    username: str
    permission: RepositoryPermission = RepositoryPermission.READ


@dataclass
class RepositoryStatistics(BaseDTO):
    """Repository statistics and metrics."""
    repository_id: UUID
    total_commits: int
    total_branches: int
    total_tags: int
    contributors_count: int
    disk_usage_bytes: int
    last_commit_at: Optional[datetime] = None
    
    # Activity metrics
    commits_last_month: int = 0
    commits_last_week: int = 0
    active_branches: int = 0


@dataclass
class GitRef(BaseDTO):
    """Git reference information."""
    name: str
    ref_type: str  # branch, tag
    target: str  # commit SHA
    
    @property
    def short_name(self) -> str:
        """Get short reference name without prefix.
        
        Returns:
            Short name (e.g., "main" instead of "refs/heads/main")
        """
        if self.name.startswith("refs/heads/"):
            return self.name[11:]
        elif self.name.startswith("refs/tags/"):
            return self.name[10:]
        return self.name


@dataclass
class RepositoryRefs(BaseDTO):
    """Repository references (branches and tags)."""
    repository_id: UUID
    default_branch: str
    branches: List[GitRef] = field(default_factory=list)
    tags: List[GitRef] = field(default_factory=list)


@dataclass
class GitServiceType(str, Enum):
    """Git service types for HTTP protocol."""
    UPLOAD_PACK = "git-upload-pack"  # Clone/fetch
    RECEIVE_PACK = "git-receive-pack"  # Push


@dataclass
class GitOperationRequest(BaseDTO):
    """Request for Git protocol operations."""
    repository_path: str
    service: GitServiceType
    advertise_refs: bool = False
    content_type: Optional[str] = None
    
    @property
    def is_read_operation(self) -> bool:
        """Check if this is a read-only operation.
        
        Returns:
            True for read operations (clone/fetch)
        """
        return self.service == GitServiceType.UPLOAD_PACK


@dataclass
class RepositoryAccessLog(BaseDTO):
    """Log entry for repository access."""
    repository_id: UUID
    user_id: Optional[UUID]
    operation: str  # clone, fetch, push
    ip_address: str
    user_agent: Optional[str]
    timestamp: datetime
    success: bool
    bytes_transferred: Optional[int] = None