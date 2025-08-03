"""User management service.

This service orchestrates user-related operations by combining Core business logic
with Infrastructure components while managing transactions and errors.
"""

from typing import Optional, Callable
from uuid import UUID
from datetime import datetime
import structlog

from src.core.user.validator import UserValidator
from src.core.user.creator import UserCreator
from src.core.auth.password_hasher import PasswordHasher
from src.core.types import UserId
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.application.services.base import ServiceBase
from src.application.dto.user_dto import (
    RegisterUserRequest,
    UserDTO,
    UpdateProfileRequest,
    ChangePasswordRequest
)
from src.application.dto.common_dto import Result, ErrorCode, PagedResult, PaginationParams
from src.application.exceptions.service_exceptions import (
    ValidationError,
    ConflictError,
    NotFoundError,
    AuthenticationError
)

logger = structlog.get_logger()


class UserService(ServiceBase):
    """Service for user management operations.
    
    Handles user registration, authentication, profile management, and related
    operations by orchestrating Core components and Infrastructure repositories.
    """
    
    def __init__(
        self,
        user_validator: UserValidator,
        password_hasher: PasswordHasher,
        user_creator: UserCreator,
        unit_of_work_factory: Callable[[], UnitOfWork]
    ):
        """Initialize user service.
        
        Args:
            user_validator: Validator for user input
            password_hasher: Password hashing service
            user_creator: User entity creator
            unit_of_work_factory: Factory for creating unit of work instances
        """
        super().__init__()
        self.user_validator = user_validator
        self.password_hasher = password_hasher
        self.user_creator = user_creator
        self.unit_of_work_factory = unit_of_work_factory
    
    async def initialize(self) -> None:
        """Initialize service resources."""
        self.logger.info("UserService initialized")
    
    async def cleanup(self) -> None:
        """Cleanup service resources."""
        self.logger.info("UserService cleanup")
    
    async def register_user(self, request: RegisterUserRequest) -> Result[UserDTO]:
        """Register a new user.
        
        Args:
            request: User registration request
            
        Returns:
            Result containing created user DTO or error
        """
        try:
            # Validate input
            validation_errors = []
            
            username_result = self.user_validator.validate_username(request.username)
            if not username_result.is_valid:
                validation_errors.extend(username_result.errors)
            
            email_result = self.user_validator.validate_email(request.email)
            if not email_result.is_valid:
                validation_errors.extend(email_result.errors)
            
            password_result = self.user_validator.validate_password(
                request.password,
                request.username
            )
            if not password_result.is_valid:
                validation_errors.extend(password_result.errors)
            
            if validation_errors:
                return Result.fail(
                    "Validation failed",
                    ErrorCode.VALIDATION_ERROR,
                    validation_errors
                )
            
            async with self.unit_of_work_factory() as uow:
                # Check uniqueness
                if await uow.users.exists_by_username(request.username):
                    return Result.fail(
                        f"Username '{request.username}' already exists",
                        ErrorCode.CONFLICT
                    )
                
                if await uow.users.exists_by_email(request.email):
                    return Result.fail(
                        f"Email '{request.email}' already exists",
                        ErrorCode.CONFLICT
                    )
                
                # Hash password
                password_hash = self.password_hasher.hash_password(request.password)
                
                # Create user
                user_data = self.user_creator.prepare_user_data(
                    username=request.username,
                    email=request.email,
                    password_hash=password_hash
                )
                
                created_user = self.user_creator.create_user(user_data)
                
                # Save to database
                user_model = await uow.users.create({
                    'id': created_user.id,
                    'username': created_user.username,
                    'email': created_user.email,
                    'password_hash': password_hash,
                    'is_active': True,
                    'is_admin': False
                })
                
                await uow.commit()
                
                # Convert to DTO
                user_dto = UserDTO.from_model(user_model)
                
                self.logger.info(
                    "User registered successfully",
                    user_id=str(user_dto.id),
                    username=user_dto.username
                )
                
                return Result.ok(user_dto)
                
        except Exception as e:
            self.logger.error(
                "Failed to register user",
                error=str(e),
                username=request.username
            )
            return Result.fail(
                "Failed to register user",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def authenticate_user(
        self,
        username_or_email: str,
        password: str
    ) -> Result[UserDTO]:
        """Authenticate user with username/email and password.
        
        Args:
            username_or_email: Username or email
            password: User password
            
        Returns:
            Result containing authenticated user DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Find user by username or email
                user = await uow.users.find_by_username(username_or_email)
                if not user:
                    user = await uow.users.find_by_email(username_or_email)
                
                if not user:
                    return Result.fail(
                        "Invalid credentials",
                        ErrorCode.UNAUTHORIZED
                    )
                
                # Verify password
                if not self.password_hasher.verify_password(password, user.password_hash):
                    return Result.fail(
                        "Invalid credentials",
                        ErrorCode.UNAUTHORIZED
                    )
                
                # Check if user is active
                if not user.is_active:
                    return Result.fail(
                        "User account is inactive",
                        ErrorCode.FORBIDDEN
                    )
                
                # Update last login
                user.last_login_at = datetime.utcnow()
                await uow.commit()
                
                return Result.ok(UserDTO.from_model(user))
                
        except Exception as e:
            self.logger.error("Authentication failed", error=str(e))
            return Result.fail(
                "Authentication failed",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def get_user_by_id(self, user_id: UUID) -> Result[UserDTO]:
        """Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            Result containing user DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                user = await uow.users.find_by_id(user_id)
                
                if not user:
                    return Result.fail(
                        f"User not found: {user_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                return Result.ok(UserDTO.from_model(user))
                
        except Exception as e:
            self.logger.error(
                "Failed to get user",
                error=str(e),
                user_id=str(user_id)
            )
            return Result.fail(
                "Failed to get user",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def get_user_by_username(self, username: str) -> Result[UserDTO]:
        """Get user by username.
        
        Args:
            username: Username
            
        Returns:
            Result containing user DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                user = await uow.users.find_by_username(username)
                
                if not user:
                    return Result.fail(
                        f"User not found: {username}",
                        ErrorCode.NOT_FOUND
                    )
                
                return Result.ok(UserDTO.from_model(user))
                
        except Exception as e:
            self.logger.error(
                "Failed to get user",
                error=str(e),
                username=username
            )
            return Result.fail(
                "Failed to get user",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def update_profile(
        self,
        user_id: UUID,
        request: UpdateProfileRequest
    ) -> Result[UserDTO]:
        """Update user profile.
        
        Args:
            user_id: User ID
            request: Profile update request
            
        Returns:
            Result containing updated user DTO or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                user = await uow.users.find_by_id(user_id)
                
                if not user:
                    return Result.fail(
                        f"User not found: {user_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Validate and update email if provided
                if request.email and request.email != user.email:
                    email_result = self.user_validator.validate_email(request.email)
                    if not email_result.is_valid:
                        return Result.fail(
                            "Invalid email",
                            ErrorCode.VALIDATION_ERROR,
                            email_result.errors
                        )
                    
                    # Check email uniqueness
                    if await uow.users.exists_by_email(request.email):
                        return Result.fail(
                            f"Email '{request.email}' already exists",
                            ErrorCode.CONFLICT
                        )
                    
                    user.email = request.email
                
                # Update other fields
                if request.full_name is not None:
                    user.full_name = request.full_name
                
                if request.bio is not None:
                    user.bio = request.bio
                
                user.updated_at = datetime.utcnow()
                await uow.commit()
                
                self.logger.info(
                    "User profile updated",
                    user_id=str(user_id)
                )
                
                return Result.ok(UserDTO.from_model(user))
                
        except Exception as e:
            self.logger.error(
                "Failed to update profile",
                error=str(e),
                user_id=str(user_id)
            )
            return Result.fail(
                "Failed to update profile",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def change_password(
        self,
        user_id: UUID,
        request: ChangePasswordRequest
    ) -> Result[bool]:
        """Change user password.
        
        Args:
            user_id: User ID
            request: Password change request
            
        Returns:
            Result indicating success or failure
        """
        try:
            async with self.unit_of_work_factory() as uow:
                user = await uow.users.find_by_id(user_id)
                
                if not user:
                    return Result.fail(
                        f"User not found: {user_id}",
                        ErrorCode.NOT_FOUND
                    )
                
                # Verify current password
                if not self.password_hasher.verify_password(
                    request.current_password,
                    user.password_hash
                ):
                    return Result.fail(
                        "Current password is incorrect",
                        ErrorCode.UNAUTHORIZED
                    )
                
                # Validate new password
                password_result = self.user_validator.validate_password(
                    request.new_password,
                    user.username
                )
                if not password_result.is_valid:
                    return Result.fail(
                        "Invalid new password",
                        ErrorCode.VALIDATION_ERROR,
                        password_result.errors
                    )
                
                # Hash and update password
                new_hash = self.password_hasher.hash_password(request.new_password)
                user.password_hash = new_hash
                user.updated_at = datetime.utcnow()
                
                await uow.commit()
                
                self.logger.info(
                    "User password changed",
                    user_id=str(user_id)
                )
                
                return Result.ok(True)
                
        except Exception as e:
            self.logger.error(
                "Failed to change password",
                error=str(e),
                user_id=str(user_id)
            )
            return Result.fail(
                "Failed to change password",
                ErrorCode.INTERNAL_ERROR
            )
    
    async def list_users(
        self,
        pagination: PaginationParams,
        search: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Result[PagedResult[UserDTO]]:
        """List users with pagination and filtering.
        
        Args:
            pagination: Pagination parameters
            search: Optional search term
            is_active: Optional active status filter
            
        Returns:
            Result containing paginated users or error
        """
        try:
            async with self.unit_of_work_factory() as uow:
                # Build filter conditions
                filters = {}
                if search:
                    filters['search'] = search
                if is_active is not None:
                    filters['is_active'] = is_active
                
                # Get paginated results
                users = await uow.users.find_all(
                    offset=pagination.offset,
                    limit=pagination.limit,
                    filters=filters
                )
                
                total = await uow.users.count(filters=filters)
                
                # Convert to DTOs
                user_dtos = [UserDTO.from_model(user) for user in users]
                
                return Result.ok(PagedResult(
                    items=user_dtos,
                    total=total,
                    page=pagination.page,
                    per_page=pagination.per_page
                ))
                
        except Exception as e:
            self.logger.error("Failed to list users", error=str(e))
            return Result.fail(
                "Failed to list users",
                ErrorCode.INTERNAL_ERROR
            )