"""Repository management service.

This service orchestrates repository operations including creation, deletion,
and management by combining Core business logic with Infrastructure components.
"""

from typing import Optional, Callable, List
from uuid import UUID
from pathlib import Path
from datetime import datetime
import structlog

from src.core.repository.validator import RepositoryValidator
from src.core.repository.initializer import RepositoryInitializer
from src.core.repository.path_resolver import RepositoryPathResolver
from src.core.repository.remover import RepositoryRemover
from src.core.repository.info_reader import RepositoryInfoReader
from src.core.git.command_executor import GitCommandExecutor
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.infrastructure.filesystem.directory_manager import DirectoryManager
from src.infrastructure.filesystem.path_sanitizer import PathSanitizer
from src.application.services.base import ServiceBase
from src.application.dto.repository_dto import (
    CreateRepositoryRequest,
    UpdateRepositoryRequest,
    RepositoryDTO,
    RepositoryFilter,
    CloneURLs,
    AddCollaboratorRequest,
    RepositoryCollaborator,
    RepositoryPermission
)
from src.application.dto.common_dto import Result, ErrorCode, PagedResult, PaginationParams
from src.application.dto.user_dto import PublicUserDTO
from src.application.exceptions.service_exceptions import (
    ValidationError,
    ConflictError,
    NotFoundError,
    AuthorizationError,
    ServiceError
)

logger = structlog.get_logger()


class RepositoryService(ServiceBase):
    """Service for repository management operations.
    
    Handles repository creation, deletion, updates, and access control
    by orchestrating Core components and Infrastructure repositories.
    """
    
    def __init__(
        self,
        repository_validator: RepositoryValidator,
        repository_initializer: RepositoryInitializer,
        path_resolver: RepositoryPathResolver,
        repository_remover: RepositoryRemover,
        info_reader: RepositoryInfoReader,
        directory_manager: DirectoryManager,
        path_sanitizer: PathSanitizer,
        git_executor: GitCommandExecutor,
        unit_of_work_factory: Callable[[], UnitOfWork],
        base_url: str
    ):
        """Initialize repository service.
        
        Args:
            repository_validator: Repository name validator
            repository_initializer: Git repository initializer
            path_resolver: Repository path resolver
            repository_remover: Repository removal service
            info_reader: Repository information reader
            directory_manager: Directory management service
            path_sanitizer: Path security validator
            git_executor: Git command executor
            unit_of_work_factory: Factory for creating unit of work instances
            base_url: Base URL for generating clone URLs
        """
        super().__init__()
        self.repository_validator = repository_validator
        self.repository_initializer = repository_initializer
        self.path_resolver = path_resolver
        self.repository_remover = repository_remover
        self.info_reader = info_reader
        self.directory_manager = directory_manager
        self.path_sanitizer = path_sanitizer
        self.git_executor = git_executor
        self.unit_of_work_factory = unit_of_work_factory
        self.base_url = base_url
    
    async def initialize(self) -> None:
        """Initialize service resources."""
        self.logger.info("RepositoryService initialized")
    
    async def cleanup(self) -> None:
        """Cleanup service resources."""
        self.logger.info("RepositoryService cleanup")
    
    async def create_repository(
        self,
        owner_id: UUID,
        request: CreateRepositoryRequest
    ) -> Result[RepositoryDTO]:
        """Create a new repository.
        
        Args:
            owner_id: Repository owner ID
            request: Repository creation request
            
        Returns:
            Result containing created repository DTO or error
        """
        try:
            # Validate repository name
            validation_result = self.repository_validator.validate_name(request.name)
            if not validation_result.is_valid:
                return Result.fail(
                    "Invalid repository name",
                    ErrorCode.VALIDATION_ERROR,
                    validation_result.errors
                )
            
            async with self.unit_of_work_factory() as uow:
                # Get owner info
                owner = await uow.users.find_by_id(owner_id)
                if not owner:
                    return Result.fail(
                        "Owner not found",
                        ErrorCode.NOT_FOUND
                    )
                
                # Check if repository already exists
                existing = await uow.repositories.find_by_owner_and_name(
                    owner_id,
                    request.name
                )
                if existing:
                    return Result.fail(
                        f"Repository '{request.name}' already exists",
                        ErrorCode.CONFLICT
                    )
                
                # Calculate repository path
                repo_path = self.path_resolver.get_repository_path(
                    owner.username,
                    request.name
                )
                
                # Validate path security
                if not self.path_sanitizer.is_safe_path(str(repo_path)):
                    return Result.fail(
                        "Invalid repository path",
                        ErrorCode.VALIDATION_ERROR
                    )
                
                # Create directory
                await self.directory_manager.create_directory(repo_path.parent)
                
                try:
                    # Initialize Git repository
                    await self.repository_initializer.init_bare_repository(
                        repo_path,
                        {
                            "description": request.description or f"{owner.username}/{request.name}",
                            "default_branch": request.default_branch
                        }
                    )
                    
                    # Update server info for HTTP access
                    await self.git_executor.execute(
                        ["update-server-info"],
                        cwd=str(repo_path)
                    )
                    
                    # Save to database
                    repo_model = await uow.repositories.create({
                        'name': request.name,
                        'owner_id': owner_id,
                        'description': request.description,
                        'is_private': request.is_private,
                        'default_branch': request.default_branch,
                        'size_bytes': 0
                    })
                    
                    await uow.commit()
                    
                    # Create DTO with clone URLs
                    repo_dto = self._create_repository_dto(repo_model, owner)
                    
                    self.logger.info(
                        "Repository created successfully",
                        repo_id=str(repo_dto.id),
                        owner=owner.username,
                        name=request.name
                    )
                    
                    return Result.ok(repo_dto)
                    
                except Exception as e:
                    # Rollback filesystem changes
                    await self.directory_manager.delete_directory(repo_path, force=True)
                    raise
                    
        except Exception as e:
            self.logger.error(
                "Failed to create repository",
                error=str(e),
                owner_id=str(owner_id),
                name=request.name
            )
            return Result.fail(
                "Failed to create repository",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def get_repository(
        self,
        owner: str,
        name: str,
        user_id: Optional[UUID] = None
    ) -> Result[RepositoryDTO]:
        """Get repository by owner and name.
        
        Args:
            owner: Repository owner username
            name: Repository name
            user_id: Optional user ID for permission checking
            
        Returns:
            Result containing repository DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Find repository with owner
                repo = await uow.repositories.find_by_owner_and_name_with_owner(
                    owner,
                    name
                )
                
                if not repo:
                    return Result.fail(
                        f"Repository not found: {owner}/{name}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Check access permissions
                if repo.is_private and user_id:
                    if not await self._has_repository_access(
                        user_id,
                        repo.id,
                        uow
                    ):
                        return Result.fail(
                            "Access denied",
                            ErrorCode.FORBIDDEN
                        )
                elif repo.is_private and not user_id:
                    return Result.fail(
                        "Authentication required",
                        ErrorCode.UNAUTHORIZED
                    )
                
                # Update repository size if needed
                repo_path = self.path_resolver.get_repository_path(
                    repo.owner.username,
                    repo.name
                )
                current_size = await self.directory_manager.get_directory_size(repo_path)
                
                if current_size != repo.size_bytes:
                    repo.size_bytes = current_size
                    await uow.commit()
                
                return Result.ok(self._create_repository_dto(repo, repo.owner))
                
        except Exception as e:
            self.logger.error(
                "Failed to get repository",
                error=str(e),
                owner=owner,
                name=name
            )
            return Result.fail(
                "Failed to get repository",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def update_repository(
        self,
        owner_id: UUID,
        repo_id: UUID,
        request: UpdateRepositoryRequest
    ) -> Result[RepositoryDTO]:
        """Update repository settings.
        
        Args:
            owner_id: Repository owner ID
            repo_id: Repository ID
            request: Update request
            
        Returns:
            Result containing updated repository DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Get repository
                repo = await uow.repositories.find_by_id_with_owner(repo_id)
                
                if not repo:
                    return Result.fail(
                        f"Repository not found: {repo_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Verify ownership
                if repo.owner_id != owner_id:
                    return Result.fail(
                        "Permission denied",
                        ErrorCode.FORBIDDEN
                    )
                
                # Update fields
                updated = False
                
                if request.name and request.name != repo.name:
                    # Validate new name
                    validation_result = self.repository_validator.validate_name(request.name)
                    if not validation_result.is_valid:
                        return Result.fail(
                            "Invalid repository name",
                            ErrorCode.VALIDATION_ERROR,
                            validation_result.errors
                        )
                    
                    # Check uniqueness
                    existing = await uow.repositories.find_by_owner_and_name(
                        owner_id,
                        request.name
                    )
                    if existing:
                        return Result.fail(
                            f"Repository '{request.name}' already exists",
                            ErrorCode.CONFLICT
                        )
                    
                    # TODO: Rename repository directory
                    repo.name = request.name
                    updated = True
                
                if request.description is not None:
                    repo.description = request.description
                    updated = True
                
                if request.is_private is not None:
                    repo.is_private = request.is_private
                    updated = True
                
                if request.default_branch is not None:
                    repo.default_branch = request.default_branch
                    updated = True
                
                if request.archived is not None:
                    repo.is_archived = request.archived
                    updated = True
                
                if updated:
                    repo.updated_at = datetime.utcnow()
                    await uow.commit()
                
                self.logger.info(
                    "Repository updated",
                    repo_id=str(repo_id),
                    updated=updated
                )
                
                return Result.ok(self._create_repository_dto(repo, repo.owner))
                
        except Exception as e:
            self.logger.error(
                "Failed to update repository",
                error=str(e),
                repo_id=str(repo_id)
            )
            return Result.fail(
                "Failed to update repository",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def delete_repository(
        self,
        owner_id: UUID,
        repo_id: UUID,
        archive: bool = True
    ) -> Result[bool]:
        """Delete a repository.
        
        Args:
            owner_id: Repository owner ID
            repo_id: Repository ID
            archive: Whether to archive before deletion
            
        Returns:
            Result indicating success or failure
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Get repository
                repo = await uow.repositories.find_by_id_with_owner(repo_id)
                
                if not repo:
                    return Result.fail(
                        f"Repository not found: {repo_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Verify ownership
                if repo.owner_id != owner_id:
                    return Result.fail(
                        "Permission denied",
                        ErrorCode.FORBIDDEN
                    )
                
                # Get repository path
                repo_path = self.path_resolver.get_repository_path(
                    repo.owner.username,
                    repo.name
                )
                
                # Archive or remove repository
                if archive:
                    await self.repository_remover.archive_repository(
                        repo_path,
                        repo.owner.username,
                        repo.name
                    )
                else:
                    await self.repository_remover.remove_repository(repo_path)
                
                # Delete from database
                await uow.repositories.delete(repo_id)
                
                # Clean up related data (permissions, tokens, etc.)
                await uow.permissions.delete_by_repository(repo_id)
                
                await uow.commit()
                
                self.logger.info(
                    "Repository deleted",
                    repo_id=str(repo_id),
                    archived=archive
                )
                
                return Result.ok(True)
                
        except Exception as e:
            self.logger.error(
                "Failed to delete repository",
                error=str(e),
                repo_id=str(repo_id)
            )
            return Result.fail(
                "Failed to delete repository",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def list_repositories(
        self,
        filter: RepositoryFilter,
        pagination: PaginationParams,
        user_id: Optional[UUID] = None
    ) -> Result[PagedResult[RepositoryDTO]]:
        """List repositories with filtering and pagination.
        
        Args:
            filter: Repository filter parameters
            pagination: Pagination parameters
            user_id: Optional user ID for permission filtering
            
        Returns:
            Result containing paginated repositories or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Build query filters
                filters = {}
                
                if filter.owner_id:
                    filters['owner_id'] = filter.owner_id
                elif filter.owner_username:
                    owner = await uow.users.find_by_username(filter.owner_username)
                    if owner:
                        filters['owner_id'] = owner.id
                    else:
                        # No owner found, return empty result
                        return Result.ok(PagedResult(
                            items=[],
                            total=0,
                            page=pagination.page,
                            per_page=pagination.per_page
                        ))
                
                if filter.visibility:
                    filters['is_private'] = filter.visibility == 'private'
                
                if filter.is_archived is not None:
                    filters['is_archived'] = filter.is_archived
                
                if filter.search:
                    filters['search'] = filter.search
                
                # Get repositories
                repos = await uow.repositories.find_all_with_owner(
                    offset=pagination.offset,
                    limit=pagination.limit,
                    filters=filters,
                    sort_by=filter.sort_by,
                    sort_order=filter.sort_order
                )
                
                total = await uow.repositories.count(filters=filters)
                
                # Filter by permissions if user is provided
                if user_id:
                    # TODO: Implement permission filtering
                    pass
                
                # Convert to DTOs
                repo_dtos = [
                    self._create_repository_dto(repo, repo.owner)
                    for repo in repos
                    if not repo.is_private or (user_id and await self._has_repository_access(
                        user_id, repo.id, uow
                    ))
                ]
                
                return Result.ok(PagedResult(
                    items=repo_dtos,
                    total=total,
                    page=pagination.page,
                    per_page=pagination.per_page
                ))
                
        except Exception as e:
            self.logger.error("Failed to list repositories", error=str(e))
            return Result.fail(
                "Failed to list repositories",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def add_collaborator(
        self,
        owner_id: UUID,
        repo_id: UUID,
        request: AddCollaboratorRequest
    ) -> Result[RepositoryCollaborator]:
        """Add collaborator to repository.
        
        Args:
            owner_id: Repository owner ID
            repo_id: Repository ID
            request: Add collaborator request
            
        Returns:
            Result containing collaborator info or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Verify repository ownership
                repo = await uow.repositories.find_by_id(repo_id)
                if not repo or repo.owner_id != owner_id:
                    return Result.fail(
                        "Repository not found or access denied",
                        ErrorCode.NOT_FOUND
                    )
                
                # Find collaborator user
                collaborator = await uow.users.find_by_username(request.username)
                if not collaborator:
                    return Result.fail(
                        f"User not found: {request.username}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Check if already a collaborator
                existing = await uow.permissions.get_user_permission(
                    collaborator.id,
                    repo_id
                )
                if existing:
                    return Result.fail(
                        f"User '{request.username}' is already a collaborator",
                        ErrorCode.CONFLICT
                    )
                
                # Add permission
                permission = await uow.permissions.create({
                    'user_id': collaborator.id,
                    'repository_id': repo_id,
                    'permission': request.permission.value,
                    'granted_by': owner_id
                })
                
                await uow.commit()
                
                # Create DTO
                owner = await uow.users.find_by_id(owner_id)
                collaborator_dto = RepositoryCollaborator(
                    user=PublicUserDTO.from_model(collaborator),
                    permission=request.permission,
                    added_at=permission.created_at,
                    added_by=PublicUserDTO.from_model(owner)
                )
                
                self.logger.info(
                    "Collaborator added",
                    repo_id=str(repo_id),
                    collaborator=request.username,
                    permission=request.permission.value
                )
                
                return Result.ok(collaborator_dto)
                
        except Exception as e:
            self.logger.error(
                "Failed to add collaborator",
                error=str(e),
                repo_id=str(repo_id)
            )
            return Result.fail(
                "Failed to add collaborator",
                ErrorCode.INTERNAL_ERROR
            )
    
    def _create_repository_dto(self, repo_model, owner_model) -> RepositoryDTO:
        """Create repository DTO with clone URLs.
        
        Args:
            repo_model: Repository database model
            owner_model: Owner database model
            
        Returns:
            RepositoryDTO instance
        """
        return RepositoryDTO.from_model(repo_model, self.base_url)
    
    async def _has_repository_access(
        self,
        user_id: UUID,
        repo_id: UUID,
        uow: UnitOfWork,
        write_access: bool = False
    ) -> bool:
        """Check if user has access to repository.
        
        Args:
            user_id: User ID
            repo_id: Repository ID
            uow: Unit of work instance
            write_access: Whether to check for write access
            
        Returns:
            True if user has required access
        """
        repo = await uow.repositories.find_by_id(repo_id)
        
        # Owner always has access
        if repo.owner_id == user_id:
            return True
        
        # Check permissions
        if write_access:
            perm = await uow.permissions.get_user_permission(user_id, repo_id)
            return perm and perm.permission in ['write', 'admin']
        else:
            # For read, check if repo is public or user has any permission
            if not repo.is_private:
                return True
            perm = await uow.permissions.get_user_permission(user_id, repo_id)
            return perm is not None