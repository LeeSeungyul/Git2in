"""Namespace management API endpoints"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import (APIRouter, Depends, HTTPException, Query, Request,
                     Response, status)
from fastapi.responses import JSONResponse

from src.api.auth.dependencies import get_current_token, require_admin
from src.api.v1.models.common import (ResourceCreatedResponse,
                                      ResourceDeletedResponse,
                                      ResourceUpdatedResponse)
from src.api.v1.models.errors import ErrorCode, ErrorResponse
from src.api.v1.models.namespace import (NamespaceCreateRequest,
                                         NamespaceFilterParams,
                                         NamespaceMemberRequest,
                                         NamespaceMemberResponse,
                                         NamespaceResponse,
                                         NamespaceUpdateRequest)
from src.api.v1.models.pagination import (PaginatedResponse, PaginationParams,
                                          SortParams, create_link_header,
                                          get_pagination_params,
                                          get_sort_params)
from src.core.auth.models import TokenClaims
from src.core.models.namespace import Namespace as NamespaceModel
from src.core.services.namespace import NamespaceService
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)
router = APIRouter(prefix="/namespaces", tags=["namespaces"])

# Initialize service (in production, this would be dependency injected)
namespace_service = NamespaceService()


@router.get(
    "",
    response_model=PaginatedResponse[NamespaceResponse],
    summary="List namespaces",
    description="List all namespaces with pagination and filtering",
)
async def list_namespaces(
    request: Request,
    response: Response,
    pagination: PaginationParams = Depends(get_pagination_params),
    sort: SortParams = Depends(get_sort_params),
    search: Optional[str] = Query(None, description="Search in name and description"),
    visibility: Optional[str] = Query(
        None, pattern="^(public|private)$", description="Filter by visibility"
    ),
    owner_id: Optional[UUID] = Query(None, description="Filter by owner"),
    current_token: Optional[TokenClaims] = Depends(get_current_token),
):
    """List all namespaces with pagination and filtering"""

    correlation_id = get_correlation_id()

    try:
        # Build filter params
        filters = NamespaceFilterParams(
            search=search, visibility=visibility, owner_id=owner_id
        )

        # Get namespaces from service
        namespaces, total = await namespace_service.list_namespaces(
            offset=pagination.get_offset(),
            limit=pagination.get_limit(),
            filters=filters,
            sort_by=sort.sort_by,
            sort_desc=sort.is_descending,
            user_id=UUID(current_token.sub) if current_token else None,
        )

        # Convert to response models
        namespace_responses = [
            NamespaceResponse(
                id=ns.id,
                name=ns.name,
                display_name=ns.display_name,
                description=ns.description,
                visibility=ns.visibility,
                owner_id=ns.owner_id,
                repository_count=ns.repository_count,
                created_at=ns.created_at,
                updated_at=ns.updated_at,
            )
            for ns in namespaces
        ]

        # Create paginated response
        paginated = PaginatedResponse.create(
            items=namespace_responses,
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
            "namespaces_listed",
            count=len(namespace_responses),
            total=total,
            page=pagination.page,
            correlation_id=correlation_id,
        )

        return paginated

    except Exception as e:
        logger.error(
            "namespace_list_failed", error=str(e), correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to list namespaces", correlation_id=correlation_id
            ).model_dump(),
        )


@router.post(
    "",
    response_model=ResourceCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create namespace",
    description="Create a new namespace",
)
async def create_namespace(
    request: NamespaceCreateRequest,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Create a new namespace"""

    correlation_id = get_correlation_id()

    try:
        # Check if namespace already exists
        existing = await namespace_service.get_namespace_by_name(request.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse.conflict(
                    message=f"Namespace '{request.name}' already exists",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Create namespace model
        namespace = NamespaceModel(
            id=uuid4(),
            name=request.name,
            display_name=request.display_name or request.name,
            description=request.description,
            visibility=request.visibility,
            owner_id=UUID(current_token.sub),
            repository_count=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        # Save namespace
        created = await namespace_service.create_namespace(namespace)

        logger.info(
            "namespace_created",
            namespace_id=str(created.id),
            namespace_name=created.name,
            owner_id=str(created.owner_id),
            correlation_id=correlation_id,
        )

        return ResourceCreatedResponse(
            id=str(created.id),
            created_at=created.created_at,
            location=f"/api/v1/namespaces/{created.id}",
            message=f"Namespace '{created.name}' created successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "namespace_create_failed",
            error=str(e),
            namespace_name=request.name,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to create namespace", correlation_id=correlation_id
            ).model_dump(),
        )


@router.get(
    "/{namespace_id}",
    response_model=NamespaceResponse,
    summary="Get namespace",
    description="Get namespace by ID",
)
async def get_namespace(
    namespace_id: UUID,
    current_token: Optional[TokenClaims] = Depends(get_current_token),
):
    """Get namespace by ID"""

    correlation_id = get_correlation_id()

    try:
        namespace = await namespace_service.get_namespace(
            namespace_id, user_id=UUID(current_token.sub) if current_token else None
        )

        if not namespace:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=str(namespace_id),
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        return NamespaceResponse(
            id=namespace.id,
            name=namespace.name,
            display_name=namespace.display_name,
            description=namespace.description,
            visibility=namespace.visibility,
            owner_id=namespace.owner_id,
            repository_count=namespace.repository_count,
            created_at=namespace.created_at,
            updated_at=namespace.updated_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "namespace_get_failed",
            error=str(e),
            namespace_id=str(namespace_id),
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to get namespace", correlation_id=correlation_id
            ).model_dump(),
        )


@router.put(
    "/{namespace_id}",
    response_model=ResourceUpdatedResponse,
    summary="Update namespace",
    description="Update namespace metadata",
)
async def update_namespace(
    namespace_id: UUID,
    request: NamespaceUpdateRequest,
    current_token: TokenClaims = Depends(get_current_token),
):
    """Update namespace metadata"""

    correlation_id = get_correlation_id()

    try:
        # Get existing namespace
        namespace = await namespace_service.get_namespace(namespace_id)

        if not namespace:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=str(namespace_id),
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if namespace.owner_id != UUID(current_token.sub):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to update this namespace",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Update fields
        if request.display_name is not None:
            namespace.display_name = request.display_name
        if request.description is not None:
            namespace.description = request.description
        if request.visibility is not None:
            namespace.visibility = request.visibility

        namespace.updated_at = datetime.utcnow()

        # Save updates
        updated = await namespace_service.update_namespace(namespace)

        logger.info(
            "namespace_updated",
            namespace_id=str(namespace_id),
            updated_fields=request.model_dump(exclude_unset=True),
            correlation_id=correlation_id,
        )

        return ResourceUpdatedResponse(
            id=str(updated.id),
            updated_at=updated.updated_at,
            message=f"Namespace '{updated.name}' updated successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "namespace_update_failed",
            error=str(e),
            namespace_id=str(namespace_id),
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to update namespace", correlation_id=correlation_id
            ).model_dump(),
        )


@router.delete(
    "/{namespace_id}",
    response_model=ResourceDeletedResponse,
    summary="Delete namespace",
    description="Delete a namespace and optionally cascade delete repositories",
)
async def delete_namespace(
    namespace_id: UUID,
    cascade: bool = Query(False, description="Cascade delete repositories"),
    current_token: TokenClaims = Depends(get_current_token),
):
    """Delete a namespace"""

    correlation_id = get_correlation_id()

    try:
        # Get existing namespace
        namespace = await namespace_service.get_namespace(namespace_id)

        if not namespace:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="Namespace",
                    resource_id=str(namespace_id),
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check ownership
        if namespace.owner_id != UUID(current_token.sub):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You don't have permission to delete this namespace",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Check if namespace has repositories
        if namespace.repository_count > 0 and not cascade:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse.conflict(
                    message=f"Namespace has {namespace.repository_count} repositories. Use cascade=true to delete them",
                    correlation_id=correlation_id,
                ).model_dump(),
            )

        # Delete namespace
        await namespace_service.delete_namespace(namespace_id, cascade=cascade)

        logger.info(
            "namespace_deleted",
            namespace_id=str(namespace_id),
            namespace_name=namespace.name,
            cascade=cascade,
            correlation_id=correlation_id,
        )

        return ResourceDeletedResponse(
            id=str(namespace_id),
            deleted_at=datetime.utcnow(),
            message=f"Namespace '{namespace.name}' deleted successfully",
            correlation_id=correlation_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "namespace_delete_failed",
            error=str(e),
            namespace_id=str(namespace_id),
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to delete namespace", correlation_id=correlation_id
            ).model_dump(),
        )
