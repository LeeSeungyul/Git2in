"""Authentication and authorization service.

This service manages authentication operations including login, token management,
and permission verification.
"""

from typing import Optional, Callable, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
import hashlib
import structlog

from src.core.auth.token_generator import TokenGenerator
from src.core.auth.token_validator import TokenValidator
from src.core.auth.pat_generator import PersonalAccessTokenGenerator
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.application.services.base import ServiceBase
from src.application.services.user_service import UserService
from src.application.dto.auth_dto import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    TokenPayload,
    CreatePersonalAccessTokenRequest,
    PersonalAccessTokenDTO,
    ValidateTokenRequest,
    TokenValidationResult,
    LogoutRequest
)
from src.application.dto.common_dto import Result, ErrorCode, PagedResult, PaginationParams
from src.application.exceptions.service_exceptions import (
    AuthenticationError,
    InvalidTokenError,
    ExpiredTokenError,
    NotFoundError
)

logger = structlog.get_logger()


class AuthService(ServiceBase):
    """Service for authentication and authorization operations.
    
    Handles user authentication, token generation and validation,
    and permission management.
    """
    
    def __init__(
        self,
        user_service: UserService,
        token_generator: TokenGenerator,
        token_validator: TokenValidator,
        pat_generator: PersonalAccessTokenGenerator,
        unit_of_work_factory: Callable[[], UnitOfWork],
        access_token_ttl: timedelta = timedelta(hours=24),
        refresh_token_ttl: timedelta = timedelta(days=30)
    ):
        """Initialize authentication service.
        
        Args:
            user_service: User management service
            token_generator: JWT token generator
            token_validator: JWT token validator
            pat_generator: Personal access token generator
            unit_of_work_factory: Factory for creating unit of work instances
            access_token_ttl: Access token time-to-live
            refresh_token_ttl: Refresh token time-to-live
        """
        super().__init__()
        self.user_service = user_service
        self.token_generator = token_generator
        self.token_validator = token_validator
        self.pat_generator = pat_generator
        self.unit_of_work_factory = unit_of_work_factory
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
    
    async def initialize(self) -> None:
        """Initialize service resources."""
        self.logger.info("AuthService initialized")
    
    async def cleanup(self) -> None:
        """Cleanup service resources."""
        self.logger.info("AuthService cleanup")
    
    async def login(self, request: LoginRequest) -> Result[TokenResponse]:
        """Authenticate user and generate tokens.
        
        Args:
            request: Login request with credentials
            
        Returns:
            Result containing token response or error
        """
        try:
            # Authenticate user
            auth_result = await self.user_service.authenticate_user(
                request.username,
                request.password
            )
            
            if not auth_result.success:
                return Result.fail(
                    auth_result.error,
                    auth_result.error_code
                )
            
            user = auth_result.value
            
            # Generate tokens
            access_token = self.token_generator.generate_access_token(
                user_id=user.id,
                username=user.username,
                expires_delta=self.access_token_ttl
            )
            
            refresh_token = None
            if request.remember_me:
                refresh_token = self.token_generator.generate_refresh_token(
                    user_id=user.id,
                    expires_delta=self.refresh_token_ttl
                )
                
                # Store refresh token
                async with self.unit_of_work_factory() as uow:
                    await uow.tokens.create({
                        'user_id': user.id,
                        'token_hash': self._hash_token(refresh_token),
                        'token_type': 'refresh',
                        'expires_at': datetime.utcnow() + self.refresh_token_ttl
                    })
                    await uow.commit()
            
            response = TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                expires_in=int(self.access_token_ttl.total_seconds()),
                user=user
            )
            
            self.logger.info(
                "User logged in successfully",
                user_id=str(user.id),
                username=user.username
            )
            
            return Result.ok(response)
            
        except Exception as e:
            self.logger.error("Login failed", error=str(e))
            return Result.fail(
                "Login failed",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def logout(self, request: LogoutRequest) -> Result[bool]:
        """Logout user and invalidate tokens.
        
        Args:
            request: Logout request
            
        Returns:
            Result indicating success or failure
        """
        try:
            # Validate access token to get user info
            payload = self.token_validator.validate_token(request.access_token)
            
            if not payload:
                return Result.fail(
                    "Invalid token",
                    ErrorCode.UNAUTHORIZED
                )
            
            async with self.unit_of_work_factory() as uow:
                if request.everywhere:
                    # Invalidate all tokens for the user
                    await uow.tokens.delete_by_user(payload.user_id)
                else:
                    # Invalidate specific tokens
                    if request.refresh_token:
                        token_hash = self._hash_token(request.refresh_token)
                        await uow.tokens.delete_by_hash(token_hash)
                
                await uow.commit()
            
            self.logger.info(
                "User logged out",
                user_id=str(payload.user_id),
                everywhere=request.everywhere
            )
            
            return Result.ok(True)
            
        except Exception as e:
            self.logger.error("Logout failed", error=str(e))
            return Result.fail(
                "Logout failed",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def refresh_token(self, request: RefreshTokenRequest) -> Result[TokenResponse]:
        """Refresh access token using refresh token.
        
        Args:
            request: Refresh token request
            
        Returns:
            Result containing new token response or error
        """
        try:
            # Validate refresh token
            payload = self.token_validator.validate_token(request.refresh_token)
            
            if not payload or payload.token_type != "refresh":
                return Result.fail(
                    "Invalid refresh token",
                    ErrorCode.UNAUTHORIZED
                )
            
            async with self.unit_of_work_factory() as uow:
                # Verify refresh token exists in database
                token_hash = self._hash_token(request.refresh_token)
                stored_token = await uow.tokens.find_by_hash(token_hash)
                
                if not stored_token or stored_token.is_revoked:
                    return Result.fail(
                        "Invalid refresh token",
                        ErrorCode.UNAUTHORIZED
                    )
                
                # Check if user still exists and is active
                user = await uow.users.find_by_id(payload.user_id)
                
                if not user or not user.is_active:
                    return Result.fail(
                        "User account is not active",
                        ErrorCode.FORBIDDEN
                    )
                
                # Generate new access token
                access_token = self.token_generator.generate_access_token(
                    user_id=user.id,
                    username=user.username,
                    expires_delta=self.access_token_ttl
                )
                
                # Optionally rotate refresh token
                new_refresh_token = self.token_generator.generate_refresh_token(
                    user_id=user.id,
                    expires_delta=self.refresh_token_ttl
                )
                
                # Revoke old refresh token and store new one
                stored_token.is_revoked = True
                await uow.tokens.create({
                    'user_id': user.id,
                    'token_hash': self._hash_token(new_refresh_token),
                    'token_type': 'refresh',
                    'expires_at': datetime.utcnow() + self.refresh_token_ttl
                })
                
                await uow.commit()
                
                response = TokenResponse(
                    access_token=access_token,
                    refresh_token=new_refresh_token,
                    token_type="Bearer",
                    expires_in=int(self.access_token_ttl.total_seconds())
                )
                
                return Result.ok(response)
                
        except Exception as e:
            self.logger.error("Token refresh failed", error=str(e))
            return Result.fail(
                "Token refresh failed",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def validate_token(self, token: str) -> Result[TokenPayload]:
        """Validate access token.
        
        Args:
            token: Access token to validate
            
        Returns:
            Result containing token payload or error
        """
        try:
            payload = self.token_validator.validate_token(token)
            
            if not payload:
                return Result.fail(
                    "Invalid token",
                    ErrorCode.UNAUTHORIZED
                )
            
            # Check if token is expired
            if self.token_validator.is_token_expired(payload):
                return Result.fail(
                    "Token has expired",
                    ErrorCode.UNAUTHORIZED
                )
            
            # Check if user still exists and is active
            async with self.unit_of_work_factory() as uow:
                user = await uow.users.find_by_id(payload.user_id)
                
                if not user or not user.is_active:
                    return Result.fail(
                        "Invalid token",
                        ErrorCode.UNAUTHORIZED
                    )
            
            return Result.ok(payload)
            
        except Exception as e:
            self.logger.error("Token validation failed", error=str(e))
            return Result.fail(
                "Token validation failed",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def create_personal_access_token(
        self,
        user_id: UUID,
        request: CreatePersonalAccessTokenRequest
    ) -> Result[PersonalAccessTokenDTO]:
        """Create a personal access token.
        
        Args:
            user_id: User ID
            request: PAT creation request
            
        Returns:
            Result containing PAT DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Verify user exists
                user = await uow.users.find_by_id(user_id)
                if not user:
                    return Result.fail(
                        f"User not found: {user_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Generate token
                token, token_hash = self.pat_generator.generate_token()
                
                # Store token
                pat_model = await uow.tokens.create({
                    'name': request.name,
                    'description': request.description,
                    'user_id': user_id,
                    'token_hash': token_hash,
                    'token_type': 'pat',
                    'expires_at': request.expires_at,
                    'scopes': request.scopes,
                    'is_active': True
                })
                
                await uow.commit()
                
                # Return DTO with token (only on creation)
                pat_dto = PersonalAccessTokenDTO.from_model(pat_model, token)
                
                self.logger.info(
                    "Personal access token created",
                    user_id=str(user_id),
                    token_name=request.name
                )
                
                return Result.ok(pat_dto)
                
        except Exception as e:
            self.logger.error(
                "Failed to create PAT",
                error=str(e),
                user_id=str(user_id)
            )
            return Result.fail(
                "Failed to create personal access token",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def list_personal_access_tokens(
        self,
        user_id: UUID,
        pagination: PaginationParams
    ) -> Result[PagedResult[PersonalAccessTokenDTO]]:
        """List user's personal access tokens.
        
        Args:
            user_id: User ID
            pagination: Pagination parameters
            
        Returns:
            Result containing paginated PATs or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Get user's PATs
                tokens = await uow.tokens.find_by_user(
                    user_id,
                    token_type='pat',
                    offset=pagination.offset,
                    limit=pagination.limit
                )
                
                total = await uow.tokens.count_by_user(user_id, token_type='pat')
                
                # Convert to DTOs (without token values)
                token_dtos = [
                    PersonalAccessTokenDTO.from_model(token)
                    for token in tokens
                ]
                
                return Result.ok(PagedResult(
                    items=token_dtos,
                    total=total,
                    page=pagination.page,
                    per_page=pagination.per_page
                ))
                
        except Exception as e:
            self.logger.error(
                "Failed to list PATs",
                error=str(e),
                user_id=str(user_id)
            )
            return Result.fail(
                "Failed to list personal access tokens",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def revoke_personal_access_token(
        self,
        user_id: UUID,
        token_id: UUID
    ) -> Result[bool]:
        """Revoke a personal access token.
        
        Args:
            user_id: User ID
            token_id: Token ID to revoke
            
        Returns:
            Result indicating success or failure
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Get token
                token = await uow.tokens.find_by_id(token_id)
                
                if not token:
                    return Result.fail(
                        f"Token not found: {token_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Verify ownership
                if token.user_id != user_id:
                    return Result.fail(
                        "Permission denied",
                        ErrorCode.FORBIDDEN
                    )
                
                # Revoke token
                token.is_revoked = True
                token.updated_at = datetime.utcnow()
                
                await uow.commit()
                
                self.logger.info(
                    "Personal access token revoked",
                    user_id=str(user_id),
                    token_id=str(token_id)
                )
                
                return Result.ok(True)
                
        except Exception as e:
            self.logger.error(
                "Failed to revoke PAT",
                error=str(e),
                user_id=str(user_id),
                token_id=str(token_id)
            )
            return Result.fail(
                "Failed to revoke personal access token",
                ErrorCode.INTERNAL_ERROR
            )
    
    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage.
        
        Args:
            token: Token to hash
            
        Returns:
            Hashed token
        """
        return hashlib.sha256(token.encode()).hexdigest()