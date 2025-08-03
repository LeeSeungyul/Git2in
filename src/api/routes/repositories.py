"""Repository management routes."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from fastapi.responses import Response
import structlog

from src.api.dependencies import (
    get_repository_service,
    get_current_user,
    get_current_user_optional,
    get_current_active_user,
    check_repository_access
)
from src.api.models.repository_models import (
    CreateRepositoryRequest,
    RepositoryResponse,
    UpdateRepositoryRequest,
    RepositoryListResponse,
    RepositoryFilter
)
from src.api.models.common_models import ErrorResponse, PaginationParams
from src.application.services.repository_service import RepositoryService
from src.application.dto.user_dto import UserDTO
from src.application.dto.repository_dto import (
    CreateRepositoryDTO,
    UpdateRepositoryDTO,
    RepositoryDTO
)

logger = structlog.get_logger()
router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.post(
    "",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create repository",
    description="Create a new Git repository",
    responses={
        201: {"description": "Repository created", "model": RepositoryResponse},
        400: {"description": "Validation error", "model": ErrorResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse},
        409: {"description": "Repository name already exists", "model": ErrorResponse}
    }
)
async def create_repository(
    request: CreateRepositoryRequest,
    current_user: UserDTO = Depends(get_current_active_user),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> RepositoryResponse:
    """Create a new repository."""
    # Convert to DTO
    create_dto = CreateRepositoryDTO(
        name=request.name,
        description=request.description,
        is_private=request.is_private,
        default_branch=request.default_branch,
        owner_id=current_user.id
    )
    
    # Create repository
    result = await repository_service.create_repository(create_dto)
    
    if not result.success:
        if result.error == "REPOSITORY_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Repository '{request.name}' already exists"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )
    
    repo = result.value
    logger.info(
        "Repository created",
        repo_id=repo.id,
        owner=current_user.username,
        name=repo.name
    )
    
    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        owner=repo.owner,
        description=repo.description,
        is_private=repo.is_private,
        default_branch=repo.default_branch,
        size_bytes=repo.size_bytes,
        clone_urls=repo.clone_urls,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        last_push_at=repo.last_push_at
    )


@router.get(
    "",
    response_model=RepositoryListResponse,
    summary="List repositories",
    description="List repositories with filtering and pagination",
    responses={
        200: {"description": "Repository list", "model": RepositoryListResponse}
    }
)
async def list_repositories(
    owner: Optional[str] = Query(None, description="Filter by owner username"),
    visibility: Optional[str] = Query(None, regex="^(public|private)$", description="Filter by visibility"),
    search: Optional[str] = Query(None, description="Search in name and description"),
    sort: str = Query("updated_at", regex="^(name|created_at|updated_at|pushed_at)$", description="Sort field"),
    order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: Optional[UserDTO] = Depends(get_current_user_optional),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> RepositoryListResponse:
    """List repositories accessible to the user."""
    # Build filter
    filter_dto = RepositoryFilter(
        owner_username=owner,
        is_private=visibility == "private" if visibility else None,
        search_term=search
    )
    
    # Get repositories
    result = await repository_service.list_repositories(
        filter=filter_dto,
        current_user_id=current_user.id if current_user else None,
        skip=(page - 1) * per_page,
        limit=per_page,
        sort_by=sort,
        sort_desc=order == "desc"
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve repositories"
        )
    
    repos_data = result.value
    
    # Convert to response models
    repositories = [
        RepositoryResponse(
            id=repo.id,
            name=repo.name,
            owner=repo.owner,
            description=repo.description,
            is_private=repo.is_private,
            default_branch=repo.default_branch,
            size_bytes=repo.size_bytes,
            clone_urls=repo.clone_urls,
            created_at=repo.created_at,
            updated_at=repo.updated_at,
            last_push_at=repo.last_push_at
        )
        for repo in repos_data.repositories
    ]
    
    return RepositoryListResponse(
        repositories=repositories,
        pagination={
            "page": page,
            "per_page": per_page,
            "total": repos_data.total,
            "pages": (repos_data.total + per_page - 1) // per_page
        }
    )


@router.get(
    "/{owner}/{name}",
    response_model=RepositoryResponse,
    summary="Get repository",
    description="Get repository information",
    responses={
        200: {"description": "Repository details", "model": RepositoryResponse},
        404: {"description": "Repository not found", "model": ErrorResponse}
    }
)
async def get_repository(
    owner: str = Path(..., description="Repository owner username"),
    name: str = Path(..., description="Repository name"),
    current_user: Optional[UserDTO] = Depends(get_current_user_optional),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> RepositoryResponse:
    """Get repository information."""
    # Get repository
    result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=current_user.id if current_user else None
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repo = result.value
    
    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        owner=repo.owner,
        description=repo.description,
        is_private=repo.is_private,
        default_branch=repo.default_branch,
        size_bytes=repo.size_bytes,
        clone_urls=repo.clone_urls,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        last_push_at=repo.last_push_at
    )


@router.patch(
    "/{owner}/{name}",
    response_model=RepositoryResponse,
    summary="Update repository",
    description="Update repository settings",
    responses={
        200: {"description": "Repository updated", "model": RepositoryResponse},
        400: {"description": "Validation error", "model": ErrorResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse},
        403: {"description": "Access denied", "model": ErrorResponse},
        404: {"description": "Repository not found", "model": ErrorResponse}
    }
)
async def update_repository(
    request: UpdateRepositoryRequest,
    owner: str = Path(..., description="Repository owner username"),
    name: str = Path(..., description="Repository name"),
    current_user: UserDTO = Depends(get_current_active_user),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> RepositoryResponse:
    """Update repository settings."""
    # Check write access
    await check_repository_access(
        owner=owner,
        name=name,
        write_access=True,
        current_user=current_user,
        repository_service=repository_service
    )
    
    # Build update DTO
    update_dto = UpdateRepositoryDTO()
    
    if request.description is not None:
        update_dto.description = request.description
    
    if request.is_private is not None:
        update_dto.is_private = request.is_private
    
    if request.default_branch is not None:
        update_dto.default_branch = request.default_branch
    
    # Update repository
    result = await repository_service.update_repository(
        owner_username=owner,
        repository_name=name,
        update_dto=update_dto,
        current_user_id=current_user.id
    )
    
    if not result.success:
        if result.error == "NOT_FOUND":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )
    
    repo = result.value
    
    logger.info(
        "Repository updated",
        repo_id=repo.id,
        owner=owner,
        name=name,
        updated_by=current_user.username
    )
    
    return RepositoryResponse(
        id=repo.id,
        name=repo.name,
        owner=repo.owner,
        description=repo.description,
        is_private=repo.is_private,
        default_branch=repo.default_branch,
        size_bytes=repo.size_bytes,
        clone_urls=repo.clone_urls,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
        last_push_at=repo.last_push_at
    )


@router.delete(
    "/{owner}/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete repository",
    description="Delete a repository permanently",
    responses={
        204: {"description": "Repository deleted"},
        401: {"description": "Not authenticated", "model": ErrorResponse},
        403: {"description": "Access denied", "model": ErrorResponse},
        404: {"description": "Repository not found", "model": ErrorResponse}
    }
)
async def delete_repository(
    owner: str = Path(..., description="Repository owner username"),
    name: str = Path(..., description="Repository name"),
    archive: bool = Query(False, description="Archive instead of delete"),
    current_user: UserDTO = Depends(get_current_active_user),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> Response:
    """Delete or archive a repository."""
    # Get repository to check ownership
    result = await repository_service.get_repository(
        owner_username=owner,
        repository_name=name,
        current_user_id=current_user.id
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repo = result.value
    
    # Check if user is owner or admin
    if repo.owner.id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only repository owner or admin can delete repositories"
        )
    
    # Delete or archive repository
    if archive:
        # Archive repository (not implemented yet)
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Repository archiving not implemented yet"
        )
    else:
        # Delete repository
        delete_result = await repository_service.delete_repository(
            repository_id=repo.id,
            current_user_id=current_user.id
        )
        
        if not delete_result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete repository"
            )
    
    logger.info(
        "Repository deleted",
        repo_id=repo.id,
        owner=owner,
        name=name,
        deleted_by=current_user.username
    )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)