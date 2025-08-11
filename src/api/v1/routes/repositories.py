"""Repository management API endpoints"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import (APIRouter, BackgroundTasks, Depends, HTTPException, Query,
                     Request, Response, status)

from src.api.auth.dependencies import get_current_token
from src.api.v1.models.common import (ResourceCreatedResponse,
                                      ResourceDeletedResponse,
                                      ResourceUpdatedResponse)
from src.api.v1.models.errors import ErrorCode, ErrorResponse
from src.api.v1.models.pagination import (PaginatedResponse, PaginationParams,
                                          SortParams, create_link_header,
                                          get_pagination_params,
                                          get_sort_params)
from src.api.v1.models.repository import (RepositoryCollaboratorRequest,
                                          RepositoryCollaboratorResponse,
                                          RepositoryCreateRequest,
                                          RepositoryFilterParams,
                                          RepositoryResponse,
                                          RepositoryStatsResponse,
                                          RepositoryUpdateRequest)
from src.core.auth.models import TokenClaims
from src.core.config import settings
from src.core.models.repository import Repository as RepositoryModel
from src.core.services.namespace import NamespaceService
from src.core.services.repository import RepositoryService
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)
router = APIRouter(tags=["repositories"])

# Initialize services (in production, these would be dependency injected)
repository_service = RepositoryService()
namespace_service = NamespaceService()


@router.get(
    "/namespaces/{namespace}/repos",
    response_model=PaginatedResponse[RepositoryResponse],
    summary="List repositories in namespace",
    description="List all repositories in a namespace with pagination and filtering",
)
async def list_namespace_repositories(
    namespace: str,
    request: Request,
    response: Response,
    pagination: PaginationParams = Depends(get_pagination_params),
    sort: SortParams = Depends(get_sort_params),
    search: Optional[str] = Query(None, description="Search in name and description"),
    visibility: Optional[str] = Query(
        None, pattern="^(public|private)$", description="Filter by visibility"
    ),
    archived: Optional[bool] = Query(None, description="Filter by archive status"),
    current_token: Optional[TokenClaims] = Depends(get_current_token),
):
    """List all repositories in a namespace"""

    correlation_id = get_correlation_id()

    try:
        # Get namespace
        namespace_obj = await namespace_service.get_namespace_by_name(namespace)
        if not namespace_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=namespace,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check access to namespace
        if namespace_obj.visibility == "private":
            if not current_token or UUID(current_token.sub) != namespace_obj.owner_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=ErrorResponse.forbidden(
                        message="Access denied to private namespace",
                        correlation_id=correlation_id,
                    ).model_dump(),
                )

        # Build filter params
        filters = RepositoryFilterParams(
            search=search, visibility=visibility, archived=archived
        )

        # Get repositories from service
        repositories, total = await repository_service.list_repositories(
            namespace_id=namespace_obj.id,
            offset=pagination.get_offset(),
            limit=pagination.get_limit(),
            filters=filters,
            sort_by=sort.sort_by,
            sort_desc=sort.is_descending,
            user_id=UUID(current_token.sub) if current_token else None,
        )

        # Convert to response models
        repo_responses = [
            RepositoryResponse(
                id=repo.id,
                namespace_id=repo.namespace_id,
                namespace_name=namespace,
                name=repo.name,
                full_name=f"{namespace}/{repo.name}",
                description=repo.description,
                visibility=repo.visibility,
                default_branch=repo.default_branch,
                size_bytes=repo.size_bytes,
                star_count=0,
                fork_count=0,
                archived=repo.archived,
                created_at=repo.created_at,
                updated_at=repo.updated_at,
                last_push_at=repo.last_push_at,
                clone_url_http=f"{settings.api_host}:{settings.api_port}/git/{namespace}/{repo.name}.git",
                clone_url_ssh=None,
            )
            for repo in repositories
        ]

        # Create paginated response
        paginated = PaginatedResponse.create(
            items=repo_responses,
            total=total,
            page=pagination.page,
            per_page=pagination.per_page,
        )

        # Add pagination headers
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page"] = str(pagination.page)
        response.headers["X-Per-Page"] = str(pagination.per_page)
        response.headers["Link"] = create_link_header(
            request, pagination.page, paginated.pages, pagination.per_page
        )

        logger.info(
            "repositories_listed",
            namespace=namespace,
            count=len(repo_responses),
            total=total,
            page=pagination.page,
            correlation_id=correlation_id,
        )

        return paginated

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "repository_list_failed",
            error=str(e),
            namespace=namespace,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to list repositories", correlation_id=correlation_id
            ).model_dump(),
        )


@router.post(
    "/namespaces/{namespace}/repos",
    response_model=ResourceCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create repository",
    description="Create a new repository in a namespace",
)
async def create_repository(
    namespace: str,
    request: RepositoryCreateRequest,
    background_tasks: BackgroundTasks,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Create a new repository in a namespace"""

    correlation_id = get_correlation_id()

    try:
        # Get namespace
        namespace_obj = await namespace_service.get_namespace_by_name(namespace)
        if not namespace_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=namespace,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if namespace_obj.owner_id != UUID(current_token.sub):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to create repositories in this namespace",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check if repository already exists
        existing = await repository_service.get_repository_by_name(
            namespace_obj.id, request.name
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse.conflict(
                    message=f"Repository '{request.name}' already exists in namespace '{namespace}'",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Create repository model
        repository = RepositoryModel(
            id=uuid4(),
            namespace_id=namespace_obj.id,
            name=request.name,
            description=request.description,
            visibility=request.visibility,
            default_branch=request.default_branch,
            size_bytes=0,
            archived=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_push_at=None,
        )

        # Save repository
        created = await repository_service.create_repository(repository)

        # Update namespace repository count
        namespace_obj.repository_count += 1
        await namespace_service.update_namespace(namespace_obj)

        # Initialize Git repository in background
        background_tasks.add_task(
            repository_service.initialize_git_repository,
            namespace_name=namespace,
            repository_name=created.name,
            init_readme=request.init_readme,
            gitignore_template=request.gitignore_template,
            license_template=request.license_template,
        )

        logger.info(
            "repository_created",
            repository_id=str(created.id),
            repository_name=created.name,
            namespace=namespace,
            correlation_id=correlation_id,
        )

        return ResourceCreatedResponse(
            id=str(created.id),
            created_at=created.created_at,
            location=f"/api/v1/namespaces/{namespace}/repos/{created.name}",
            message=f"Repository '{created.name}' created successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "repository_create_failed",
            error=str(e),
            namespace=namespace,
            repository_name=request.name,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to create repository", correlation_id=correlation_id
            ).model_dump(),
        )


@router.get(
    "/namespaces/{namespace}/repos/{repo}",
    response_model=RepositoryResponse,
    summary="Get repository",
    description="Get repository details",
)
async def get_repository(
    namespace: str,
    repo: str,
    current_token: Optional[TokenClaims] = Depends(get_current_token),
):
    """Get repository details"""

    correlation_id = get_correlation_id()

    try:
        # Get namespace
        namespace_obj = await namespace_service.get_namespace_by_name(namespace)
        if not namespace_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=namespace,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Get repository
        repository = await repository_service.get_repository_by_name(
            namespace_obj.id, repo
        )
        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Repository",
                    resource_id=f"{namespace}/{repo}",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check access
        if repository.visibility == "private":
            if not current_token or UUID(current_token.sub) != namespace_obj.owner_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=ErrorResponse.forbidden(
                        message="Access denied to private repository",
                        correlation_id=correlation_id,
                    ).model_dump(),
                )

        return RepositoryResponse(
            id=repository.id,
            namespace_id=repository.namespace_id,
            namespace_name=namespace,
            name=repository.name,
            full_name=f"{namespace}/{repository.name}",
            description=repository.description,
            visibility=repository.visibility,
            default_branch=repository.default_branch,
            size_bytes=repository.size_bytes,
            star_count=0,
            fork_count=0,
            archived=repository.archived,
            created_at=repository.created_at,
            updated_at=repository.updated_at,
            last_push_at=repository.last_push_at,
            clone_url_http=f"{settings.api_host}:{settings.api_port}/git/{namespace}/{repository.name}.git",
            clone_url_ssh=None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "repository_get_failed",
            error=str(e),
            namespace=namespace,
            repo=repo,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to get repository", correlation_id=correlation_id
            ).model_dump(),
        )


@router.put(
    "/namespaces/{namespace}/repos/{repo}",
    response_model=ResourceUpdatedResponse,
    summary="Update repository",
    description="Update repository metadata",
)
async def update_repository(
    namespace: str,
    repo: str,
    request: RepositoryUpdateRequest,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Update repository metadata"""

    correlation_id = get_correlation_id()

    try:
        # Get namespace
        namespace_obj = await namespace_service.get_namespace_by_name(namespace)
        if not namespace_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=namespace,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if namespace_obj.owner_id != UUID(current_token.sub):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to update this repository",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Get repository
        repository = await repository_service.get_repository_by_name(
            namespace_obj.id, repo
        )
        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Repository",
                    resource_id=f"{namespace}/{repo}",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Update fields
        if request.description is not None:
            repository.description = request.description
        if request.visibility is not None:
            repository.visibility = request.visibility
        if request.default_branch is not None:
            repository.default_branch = request.default_branch
        if request.archived is not None:
            repository.archived = request.archived

        repository.updated_at = datetime.utcnow()

        # Save updates
        updated = await repository_service.update_repository(repository)

        logger.info(
            "repository_updated",
            repository_id=str(repository.id),
            namespace=namespace,
            repo=repo,
            updated_fields=request.model_dump(exclude_unset=True),
            correlation_id=correlation_id,
        )

        return ResourceUpdatedResponse(
            id=str(updated.id),
            updated_at=updated.updated_at,
            message=f"Repository '{namespace}/{repo}' updated successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "repository_update_failed",
            error=str(e),
            namespace=namespace,
            repo=repo,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to update repository", correlation_id=correlation_id
            ).model_dump(),
        )


@router.delete(
    "/namespaces/{namespace}/repos/{repo}",
    response_model=ResourceDeletedResponse,
    summary="Delete repository",
    description="Delete a repository",
)
async def delete_repository(
    namespace: str,
    repo: str,
    background_tasks: BackgroundTasks,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Delete a repository"""

    correlation_id = get_correlation_id()

    try:
        # Get namespace
        namespace_obj = await namespace_service.get_namespace_by_name(namespace)
        if not namespace_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=namespace,
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if namespace_obj.owner_id != UUID(current_token.sub):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to delete this repository",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Get repository
        repository = await repository_service.get_repository_by_name(
            namespace_obj.id, repo
        )
        if not repository:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Repository",
                    resource_id=f"{namespace}/{repo}",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Delete repository
        await repository_service.delete_repository(repository.id)

        # Update namespace repository count
        namespace_obj.repository_count = max(0, namespace_obj.repository_count - 1)
        await namespace_service.update_namespace(namespace_obj)

        # Clean up Git repository in background
        background_tasks.add_task(
            repository_service.cleanup_git_repository,
            namespace_name=namespace,
            repository_name=repo,
        )

        logger.info(
            "repository_deleted",
            repository_id=str(repository.id),
            namespace=namespace,
            repo=repo,
            correlation_id=correlation_id,
        )

        return ResourceDeletedResponse(
            id=str(repository.id),
            deleted_at=datetime.utcnow(),
            message=f"Repository '{namespace}/{repo}' deleted successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "repository_delete_failed",
            error=str(e),
            namespace=namespace,
            repo=repo,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to delete repository", correlation_id=correlation_id
            ).model_dump(),
        )
