"""User management API endpoints"""

from typing import List, Optional
from uuid import UUID, uuid4
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request, status
import bcrypt

from src.api.v1.models.user import (
    UserCreateRequest,
    UserUpdateRequest,
    UserResponse,
    UserPublicResponse,
    UserFilterParams,
    PasswordChangeRequest
)
from src.api.v1.models.pagination import (
    PaginationParams,
    PaginatedResponse,
    get_pagination_params,
    get_sort_params,
    SortParams,
    create_link_header
)
from src.api.v1.models.errors import ErrorResponse, ErrorCode
from src.api.v1.models.common import ResourceCreatedResponse, ResourceUpdatedResponse, ResourceDeletedResponse
from src.api.auth.dependencies import get_current_token, require_admin
from src.core.auth.models import TokenClaims
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id
from src.core.models.user import User as UserModel
from src.core.services.user import UserService

logger = get_logger(__name__)
router = APIRouter(prefix="/users", tags=["users"])

# Initialize service (in production, this would be dependency injected)
user_service = UserService()


@router.get(
    "",
    response_model=PaginatedResponse[UserPublicResponse],
    summary="List users",
    description="List all users with pagination and filtering (public information only)"
)
async def list_users(
    request: Request,
    response: Response,
    pagination: PaginationParams = Depends(get_pagination_params),
    sort: SortParams = Depends(get_sort_params),
    search: Optional[str] = Query(None, description="Search in username, email, and full name"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_token: Optional[TokenClaims] = Depends(get_current_token)
):
    """List all users (public information only)"""
    
    correlation_id = get_correlation_id()
    
    try:
        # Build filter params
        filters = UserFilterParams(
            search=search,
            is_active=is_active,
            is_admin=False  # Don't expose admin filter to non-admins
        )
        
        # Get users from service
        users, total = await user_service.list_users(
            offset=pagination.get_offset(),
            limit=pagination.get_limit(),
            filters=filters,
            sort_by=sort.sort_by,
            sort_desc=sort.is_descending
        )
        
        # Convert to public response models
        user_responses = [
            UserPublicResponse(
                id=user.id,
                username=user.username,
                full_name=user.full_name,
                bio=user.bio,
                location=user.location,
                website=user.website,
                company=user.company,
                namespace_count=0,  # Would be calculated from actual data
                repository_count=0,  # Would be calculated from actual data
                created_at=user.created_at
            )
            for user in users
        ]
        
        # Create paginated response
        paginated = PaginatedResponse.create(
            items=user_responses,
            total=total,
            page=pagination.page,
            per_page=pagination.per_page
        )
        
        # Add pagination headers
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Page"] = str(pagination.page)
        response.headers["X-Per-Page"] = str(pagination.per_page)
        response.headers["Link"] = create_link_header(request, pagination.page, paginated.pages, pagination.per_page)
        
        logger.info(
            "users_listed",
            count=len(user_responses),
            total=total,
            page=pagination.page,
            correlation_id=correlation_id
        )
        
        return paginated
        
    except Exception as e:
        logger.error(
            "user_list_failed",
            error=str(e),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to list users",
                correlation_id=correlation_id
            ).model_dump()
        )


@router.post(
    "",
    response_model=ResourceCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Register a new user"
)
async def create_user(
    request: UserCreateRequest
):
    """Register a new user"""
    
    correlation_id = get_correlation_id()
    
    try:
        # Check if username already exists
        existing = await user_service.get_user_by_username(request.username)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse.conflict(
                    message=f"Username '{request.username}' already exists",
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Check if email already exists
        existing = await user_service.get_user_by_email(request.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse.conflict(
                    message=f"Email '{request.email}' already registered",
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Hash password
        password_hash = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user model
        user = UserModel(
            id=uuid4(),
            username=request.username,
            email=request.email,
            password_hash=password_hash,
            full_name=request.full_name,
            is_active=True,
            is_admin=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Save user
        created = await user_service.create_user(user)
        
        logger.info(
            "user_created",
            user_id=str(created.id),
            username=created.username,
            email=created.email,
            correlation_id=correlation_id
        )
        
        return ResourceCreatedResponse(
            id=str(created.id),
            created_at=created.created_at,
            location=f"/api/v1/users/{created.id}",
            message=f"User '{created.username}' created successfully",
            correlation_id=correlation_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "user_create_failed",
            error=str(e),
            username=request.username,
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to create user",
                correlation_id=correlation_id
            ).model_dump()
        )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get current authenticated user's profile"
)
async def get_current_user(
    current_token: TokenClaims = Depends(get_current_token)
):
    """Get current authenticated user's profile"""
    
    correlation_id = get_correlation_id()
    
    try:
        user = await user_service.get_user(UUID(current_token.sub))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="User",
                    resource_id=current_token.sub,
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            bio=user.bio,
            location=user.location,
            website=user.website,
            company=user.company,
            is_active=user.is_active,
            is_admin=user.is_admin,
            namespace_count=0,  # Would be calculated
            repository_count=0,  # Would be calculated
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login_at=user.last_login_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "user_get_me_failed",
            error=str(e),
            user_id=current_token.sub,
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to get user profile",
                correlation_id=correlation_id
            ).model_dump()
        )


@router.get(
    "/{user_id}",
    response_model=UserPublicResponse,
    summary="Get user",
    description="Get user by ID (public information only)"
)
async def get_user(
    user_id: UUID,
    current_token: Optional[TokenClaims] = Depends(get_current_token)
):
    """Get user by ID (public information only)"""
    
    correlation_id = get_correlation_id()
    
    try:
        user = await user_service.get_user(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="User",
                    resource_id=str(user_id),
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Return full info if requesting own profile
        if current_token and UUID(current_token.sub) == user_id:
            return UserResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                full_name=user.full_name,
                bio=user.bio,
                location=user.location,
                website=user.website,
                company=user.company,
                is_active=user.is_active,
                is_admin=user.is_admin,
                namespace_count=0,
                repository_count=0,
                created_at=user.created_at,
                updated_at=user.updated_at,
                last_login_at=user.last_login_at
            )
        
        # Return public info for other users
        return UserPublicResponse(
            id=user.id,
            username=user.username,
            full_name=user.full_name,
            bio=user.bio,
            location=user.location,
            website=user.website,
            company=user.company,
            namespace_count=0,
            repository_count=0,
            created_at=user.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "user_get_failed",
            error=str(e),
            user_id=str(user_id),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to get user",
                correlation_id=correlation_id
            ).model_dump()
        )


@router.put(
    "/{user_id}",
    response_model=ResourceUpdatedResponse,
    summary="Update user",
    description="Update user profile"
)
async def update_user(
    user_id: UUID,
    request: UserUpdateRequest,
    current_token: TokenClaims = Depends(get_current_token)
):
    """Update user profile"""
    
    correlation_id = get_correlation_id()
    
    try:
        # Check authorization (can only update own profile unless admin)
        if UUID(current_token.sub) != user_id and not current_token.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You can only update your own profile",
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Get existing user
        user = await user_service.get_user(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="User",
                    resource_id=str(user_id),
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Update fields
        if request.email is not None:
            # Check if new email is already taken
            existing = await user_service.get_user_by_email(request.email)
            if existing and existing.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=ErrorResponse.conflict(
                        message=f"Email '{request.email}' already registered",
                        correlation_id=correlation_id
                    ).model_dump()
                )
            user.email = request.email
        
        if request.full_name is not None:
            user.full_name = request.full_name
        if request.bio is not None:
            user.bio = request.bio
        if request.location is not None:
            user.location = request.location
        if request.website is not None:
            user.website = request.website
        if request.company is not None:
            user.company = request.company
        
        user.updated_at = datetime.utcnow()
        
        # Save updates
        updated = await user_service.update_user(user)
        
        logger.info(
            "user_updated",
            user_id=str(user_id),
            updated_fields=request.model_dump(exclude_unset=True),
            correlation_id=correlation_id
        )
        
        return ResourceUpdatedResponse(
            id=str(updated.id),
            updated_at=updated.updated_at,
            message=f"User profile updated successfully",
            correlation_id=correlation_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "user_update_failed",
            error=str(e),
            user_id=str(user_id),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to update user",
                correlation_id=correlation_id
            ).model_dump()
        )


@router.delete(
    "/{user_id}",
    response_model=ResourceDeletedResponse,
    summary="Delete user",
    description="Delete a user account"
)
async def delete_user(
    user_id: UUID,
    current_token: TokenClaims = Depends(get_current_token)
):
    """Delete a user account"""
    
    correlation_id = get_correlation_id()
    
    try:
        # Check authorization (can only delete own account unless admin)
        if UUID(current_token.sub) != user_id and not current_token.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ErrorResponse.forbidden(
                    message="You can only delete your own account",
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Get existing user
        user = await user_service.get_user(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse.not_found(
                    resource="User",
                    resource_id=str(user_id),
                    correlation_id=correlation_id
                ).model_dump()
            )
        
        # Delete user (in production, might soft-delete instead)
        await user_service.delete_user(user_id)
        
        logger.info(
            "user_deleted",
            user_id=str(user_id),
            username=user.username,
            correlation_id=correlation_id
        )
        
        return ResourceDeletedResponse(
            id=str(user_id),
            deleted_at=datetime.utcnow(),
            message=f"User account deleted successfully",
            correlation_id=correlation_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "user_delete_failed",
            error=str(e),
            user_id=str(user_id),
            correlation_id=correlation_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.internal_error(
                message="Failed to delete user",
                correlation_id=correlation_id
            ).model_dump()
        )