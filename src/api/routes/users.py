"""User management routes."""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
import structlog

from src.api.dependencies import (
    get_user_service,
    get_auth_service,
    get_current_user,
    get_current_active_user
)
from src.api.models.user_models import (
    CreateUserRequest,
    UserResponse,
    UserProfileResponse,
    UpdateUserRequest,
    PersonalAccessTokenRequest,
    PersonalAccessTokenResponse,
    PersonalAccessTokenListResponse
)
from src.api.models.common_models import ErrorResponse
from src.application.services.user_service import UserService
from src.application.services.auth_service import AuthService
from src.application.dto.user_dto import UserDTO, CreateUserDTO, UpdateUserDTO
from src.application.dto.auth_dto import PersonalAccessTokenDTO

logger = structlog.get_logger()
router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account",
    responses={
        201: {"description": "User created successfully", "model": UserResponse},
        400: {"description": "Validation error", "model": ErrorResponse},
        409: {"description": "Username or email already exists", "model": ErrorResponse},
        429: {"description": "Too many registration attempts", "model": ErrorResponse}
    }
)
async def register_user(
    request: CreateUserRequest,
    user_service: UserService = Depends(get_user_service)
) -> UserResponse:
    """Register a new user."""
    # Convert to DTO
    create_dto = CreateUserDTO(
        username=request.username,
        email=request.email,
        password=request.password
    )
    
    # Create user
    result = await user_service.create_user(create_dto)
    
    if not result.success:
        if result.error == "USERNAME_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        elif result.error == "EMAIL_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )
    
    user = result.value
    logger.info("User registered", user_id=user.id, username=user.username)
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get current user profile",
    description="Get detailed profile information for the authenticated user",
    responses={
        200: {"description": "User profile", "model": UserProfileResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse}
    }
)
async def get_user_profile(
    current_user: UserDTO = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service)
) -> UserProfileResponse:
    """Get current user's profile with statistics."""
    # Get user statistics
    stats = await user_service.get_user_statistics(current_user.id)
    
    return UserProfileResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        repository_count=stats.repository_count,
        total_size_bytes=stats.total_size_bytes
    )


@router.patch(
    "/me",
    response_model=UserProfileResponse,
    summary="Update user profile",
    description="Update current user's profile information",
    responses={
        200: {"description": "Profile updated", "model": UserProfileResponse},
        400: {"description": "Validation error", "model": ErrorResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse},
        409: {"description": "Email already in use", "model": ErrorResponse}
    }
)
async def update_user_profile(
    request: UpdateUserRequest,
    current_user: UserDTO = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service)
) -> UserProfileResponse:
    """Update current user's profile."""
    # Build update DTO
    update_dto = UpdateUserDTO()
    
    # Update email if provided
    if request.email is not None:
        update_dto.email = request.email
    
    # Update password if provided (requires current password)
    if request.password is not None:
        if not request.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password required to change password"
            )
        update_dto.new_password = request.password
        update_dto.current_password = request.current_password
    
    # Update user
    result = await user_service.update_user(current_user.id, update_dto)
    
    if not result.success:
        if result.error == "EMAIL_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use"
            )
        elif result.error == "INVALID_PASSWORD":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )
    
    updated_user = result.value
    
    # Get updated statistics
    stats = await user_service.get_user_statistics(updated_user.id)
    
    return UserProfileResponse(
        id=updated_user.id,
        username=updated_user.username,
        email=updated_user.email,
        is_active=updated_user.is_active,
        is_admin=updated_user.is_admin,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        repository_count=stats.repository_count,
        total_size_bytes=stats.total_size_bytes
    )


@router.get(
    "/me/tokens",
    response_model=PersonalAccessTokenListResponse,
    summary="List personal access tokens",
    description="Get all personal access tokens for the current user",
    responses={
        200: {"description": "Token list", "model": PersonalAccessTokenListResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse}
    }
)
async def list_personal_access_tokens(
    current_user: UserDTO = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page")
) -> PersonalAccessTokenListResponse:
    """List user's personal access tokens."""
    # Get tokens with pagination
    result = await auth_service.list_personal_access_tokens(
        current_user.id,
        skip=(page - 1) * per_page,
        limit=per_page
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tokens"
        )
    
    tokens_data = result.value
    
    # Convert to response models
    tokens = [
        PersonalAccessTokenResponse(
            id=token.id,
            name=token.name,
            last_used_at=token.last_used_at,
            expires_at=token.expires_at,
            created_at=token.created_at,
            token=None  # Never expose token after creation
        )
        for token in tokens_data.tokens
    ]
    
    return PersonalAccessTokenListResponse(
        tokens=tokens,
        total=tokens_data.total
    )


@router.post(
    "/me/tokens",
    response_model=PersonalAccessTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create personal access token",
    description="Create a new personal access token for API authentication",
    responses={
        201: {"description": "Token created", "model": PersonalAccessTokenResponse},
        400: {"description": "Validation error", "model": ErrorResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse}
    }
)
async def create_personal_access_token(
    request: PersonalAccessTokenRequest,
    current_user: UserDTO = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service)
) -> PersonalAccessTokenResponse:
    """Create a new personal access token."""
    # Validate expiration
    if request.expires_at:
        if request.expires_at <= datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date must be in the future"
            )
        # Limit maximum expiration to 1 year
        max_expiration = datetime.utcnow() + timedelta(days=365)
        if request.expires_at > max_expiration:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expiration date cannot be more than 1 year in the future"
            )
    
    # Create token
    result = await auth_service.create_personal_access_token(
        user_id=current_user.id,
        name=request.name,
        expires_at=request.expires_at
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.error
        )
    
    token_data = result.value
    
    logger.info(
        "Personal access token created",
        user_id=current_user.id,
        token_id=token_data.id,
        token_name=request.name
    )
    
    return PersonalAccessTokenResponse(
        id=token_data.id,
        name=token_data.name,
        token=token_data.token,  # Only shown once!
        last_used_at=None,
        expires_at=token_data.expires_at,
        created_at=token_data.created_at
    )


@router.delete(
    "/me/tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete personal access token",
    description="Delete a personal access token",
    responses={
        204: {"description": "Token deleted"},
        401: {"description": "Not authenticated", "model": ErrorResponse},
        404: {"description": "Token not found", "model": ErrorResponse}
    }
)
async def delete_personal_access_token(
    token_id: UUID,
    current_user: UserDTO = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service)
) -> None:
    """Delete a personal access token."""
    result = await auth_service.revoke_personal_access_token(
        user_id=current_user.id,
        token_id=token_id
    )
    
    if not result.success:
        if result.error == "NOT_FOUND":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Token not found"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error
            )
    
    logger.info(
        "Personal access token deleted",
        user_id=current_user.id,
        token_id=token_id
    )