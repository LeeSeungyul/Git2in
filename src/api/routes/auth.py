"""Authentication routes."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer
import structlog

from src.api.dependencies import get_auth_service, get_current_user_optional
from src.api.models.auth_models import (
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    CurrentUserResponse
)
from src.api.models.common_models import ErrorResponse
from src.application.services.auth_service import AuthService
from src.application.dto.user_dto import UserDTO
from src.application.dto.auth_dto import LoginRequest as LoginRequestDTO

logger = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["authentication"])

# Security scheme for swagger docs
security = HTTPBearer()


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User login",
    description="Authenticate user with username/email and password",
    responses={
        200: {"description": "Login successful", "model": LoginResponse},
        400: {"description": "Invalid request format", "model": ErrorResponse},
        401: {"description": "Invalid credentials", "model": ErrorResponse},
        429: {"description": "Too many login attempts", "model": ErrorResponse}
    }
)
async def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> LoginResponse:
    """Authenticate user and return tokens."""
    # Convert to DTO
    login_dto = LoginRequestDTO(
        username=request.username,
        password=request.password
    )
    
    # Attempt login
    result = await auth_service.login(login_dto)
    
    if not result.success:
        logger.warning(
            "Login failed",
            username=request.username,
            error=result.error
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Get login response
    login_info = result.value
    
    # Build response
    return LoginResponse(
        access_token=login_info.access_token,
        refresh_token=login_info.refresh_token,
        token_type="Bearer",
        expires_in=login_info.expires_in,
        user=CurrentUserResponse(
            id=login_info.user.id,
            username=login_info.user.username,
            email=login_info.user.email,
            is_active=login_info.user.is_active,
            is_admin=login_info.user.is_admin,
            created_at=login_info.user.created_at
        )
    )


@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    summary="Refresh access token",
    description="Exchange refresh token for new access token",
    responses={
        200: {"description": "Token refreshed", "model": RefreshTokenResponse},
        400: {"description": "Invalid request", "model": ErrorResponse},
        401: {"description": "Invalid refresh token", "model": ErrorResponse}
    }
)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> RefreshTokenResponse:
    """Refresh access token using refresh token."""
    # Attempt token refresh
    result = await auth_service.refresh_token(request.refresh_token)
    
    if not result.success:
        logger.warning(
            "Token refresh failed",
            error=result.error
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Get new tokens
    token_info = result.value
    
    # Build response
    return RefreshTokenResponse(
        access_token=token_info.access_token,
        refresh_token=token_info.refresh_token,
        token_type="Bearer",
        expires_in=token_info.expires_in
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="User logout",
    description="Invalidate current access token",
    responses={
        204: {"description": "Logout successful"},
        401: {"description": "Not authenticated", "model": ErrorResponse}
    }
)
async def logout(
    response: Response,
    current_user: Optional[UserDTO] = Depends(get_current_user_optional),
    auth_service: AuthService = Depends(get_auth_service),
    authorization: Optional[str] = Depends(security)
) -> None:
    """Logout current user."""
    # If no user authenticated, still return success (idempotent)
    if not current_user or not authorization:
        return
    
    # Extract token from authorization header
    token = authorization.credentials if authorization else None
    
    if token:
        # Invalidate the token
        await auth_service.logout(token)
        logger.info(
            "User logged out",
            user_id=current_user.id,
            username=current_user.username
        )
    
    # Clear any cookies if they exist
    response.delete_cookie("access_token", httponly=True)
    response.delete_cookie("refresh_token", httponly=True)


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    summary="Get current user",
    description="Get information about the currently authenticated user",
    responses={
        200: {"description": "Current user info", "model": CurrentUserResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse}
    }
)
async def get_current_user(
    current_user: Optional[UserDTO] = Depends(get_current_user_optional)
) -> CurrentUserResponse:
    """Get current authenticated user information."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return CurrentUserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at
    )