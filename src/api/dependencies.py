"""Common dependencies for API routes."""

from typing import AsyncGenerator, Optional, Callable
from uuid import UUID
from pathlib import Path

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPBasic, HTTPBasicCredentials
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.application.services.user_service import UserService
from src.application.services.auth_service import AuthService
from src.application.services.repository_service import RepositoryService
from src.application.services.git_service import GitService
from src.application.dto.user_dto import UserDTO
from src.application.dto.auth_dto import TokenPayload
from src.application.dto.common_dto import ErrorCode
from src.infrastructure.database import DatabaseConnection, UnitOfWork
from src.infrastructure.filesystem.directory_manager import DirectoryManager
from src.infrastructure.filesystem.path_sanitizer import PathSanitizer
from src.infrastructure.http.request_parser import GitHttpRequestParser
from src.core.auth.token_generator import TokenGenerator
from src.core.auth.token_validator import TokenValidator
from src.core.auth.password_hasher import PasswordHasher
from src.core.auth.pat_generator import PersonalAccessTokenGenerator
from src.core.user.validator import UserValidator
from src.core.user.creator import UserCreator
from src.core.repository.validator import RepositoryValidator
from src.core.repository.initializer import RepositoryInitializer
from src.core.repository.path_resolver import RepositoryPathResolver
from src.core.repository.remover import RepositoryRemover
from src.core.repository.info_reader import RepositoryInfoReader
from src.core.git.command_executor import GitCommandExecutor
from src.core.git.upload_pack_service import GitUploadPackService
from src.core.git.receive_pack_service import GitReceivePackService
from src.config.settings import Settings

logger = structlog.get_logger()

# Security schemes
oauth2_scheme = HTTPBearer(auto_error=False)
basic_auth = HTTPBasic(auto_error=False)

# Settings dependency
def get_settings_dep() -> Settings:
    """Get application settings."""
    from src.config.settings import settings
    return settings

# Database session dependency
async def get_db(settings: Settings = Depends(get_settings_dep)) -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    db_connection = DatabaseConnection(settings.database_url)
    async with db_connection.get_session() as session:
        yield session

# Unit of work factory
def get_unit_of_work_factory(db: AsyncSession = Depends(get_db)) -> Callable[[], UnitOfWork]:
    """Get unit of work factory."""
    def factory() -> UnitOfWork:
        return UnitOfWork(db)
    return factory

# Service dependencies
def get_user_service(
    unit_of_work_factory: Callable[[], UnitOfWork] = Depends(get_unit_of_work_factory),
    settings: Settings = Depends(get_settings_dep)
) -> UserService:
    """Get user service instance."""
    return UserService(
        user_validator=UserValidator(),
        password_hasher=PasswordHasher(),
        user_creator=UserCreator(),
        unit_of_work_factory=unit_of_work_factory
    )

def get_auth_service(
    user_service: UserService = Depends(get_user_service),
    unit_of_work_factory: Callable[[], UnitOfWork] = Depends(get_unit_of_work_factory),
    settings: Settings = Depends(get_settings_dep)
) -> AuthService:
    """Get auth service instance."""
    return AuthService(
        user_service=user_service,
        token_generator=TokenGenerator(settings.secret_key),
        token_validator=TokenValidator(settings.secret_key),
        pat_generator=PersonalAccessTokenGenerator(),
        unit_of_work_factory=unit_of_work_factory
    )

def get_repository_service(
    unit_of_work_factory: Callable[[], UnitOfWork] = Depends(get_unit_of_work_factory),
    settings: Settings = Depends(get_settings_dep)
) -> RepositoryService:
    """Get repository service instance."""
    return RepositoryService(
        repository_validator=RepositoryValidator(),
        repository_initializer=RepositoryInitializer(settings.git_binary_path),
        path_resolver=RepositoryPathResolver(settings.repos_path),
        repository_remover=RepositoryRemover(),
        info_reader=RepositoryInfoReader(settings.git_binary_path),
        directory_manager=DirectoryManager(settings.repos_path),
        path_sanitizer=PathSanitizer(),
        git_executor=GitCommandExecutor(
            git_binary_path=settings.git_binary_path,
            timeout=settings.git_operation_timeout
        ),
        unit_of_work_factory=unit_of_work_factory,
        base_url=getattr(settings, 'base_url', 'http://localhost:8000')
    )

def get_git_service(
    auth_service: AuthService = Depends(get_auth_service),
    repository_service: RepositoryService = Depends(get_repository_service),
    unit_of_work_factory: Callable[[], UnitOfWork] = Depends(get_unit_of_work_factory),
    settings: Settings = Depends(get_settings_dep)
) -> GitService:
    """Get git service instance."""
    return GitService(
        auth_service=auth_service,
        repository_service=repository_service,
        upload_pack_service=GitUploadPackService(
            GitCommandExecutor(
                git_binary_path=settings.git_binary_path,
                timeout=settings.git_operation_timeout
            )
        ),
        receive_pack_service=GitReceivePackService(
            GitCommandExecutor(
                git_binary_path=settings.git_binary_path,
                timeout=settings.git_operation_timeout
            )
        ),
        path_resolver=RepositoryPathResolver(settings.repos_path),
        request_parser=GitHttpRequestParser(),
        unit_of_work_factory=unit_of_work_factory
    )

# Authentication dependencies
async def get_current_user_optional(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    token: Optional[HTTPBearer] = Depends(oauth2_scheme)
) -> Optional[UserDTO]:
    """Get current user if authenticated, None otherwise."""
    if not token or not token.credentials:
        return None
    
    result = await auth_service.validate_token(token.credentials)
    if not result.success:
        return None
    
    # Get user from token payload
    token_payload: TokenPayload = result.value
    async with auth_service.unit_of_work_factory() as uow:
        user = await uow.users.find_by_id(token_payload.user_id)
        if not user:
            return None
        return UserDTO.from_model(user)

async def get_current_user(
    current_user: Optional[UserDTO] = Depends(get_current_user_optional)
) -> UserDTO:
    """Get current authenticated user (required)."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user

async def get_current_active_user(
    current_user: UserDTO = Depends(get_current_user)
) -> UserDTO:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

async def get_current_admin_user(
    current_user: UserDTO = Depends(get_current_active_user)
) -> UserDTO:
    """Get current admin user."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

# Git authentication
async def get_git_credentials(
    credentials: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    auth_service: AuthService = Depends(get_auth_service)
) -> Optional[UserDTO]:
    """Get user from Git basic auth credentials."""
    if not credentials:
        return None
    
    # Check if username is a PAT token prefix
    if credentials.username in ["token", "x-access-token", "x-token-auth"]:
        # Validate PAT
        result = await auth_service.validate_personal_access_token(
            credentials.password
        )
        if result.success:
            # Get user from PAT
            pat_info = result.value
            async with auth_service.unit_of_work_factory() as uow:
                user = await uow.users.find_by_id(pat_info.user_id)
                if user:
                    return UserDTO.from_model(user)
    else:
        # Regular username/password auth
        from src.application.dto.auth_dto import LoginRequest
        login_request = LoginRequest(
            username=credentials.username,
            password=credentials.password
        )
        result = await auth_service.login(login_request)
        if result.success:
            return result.value.user
    
    return None

# Repository access helper
async def check_repository_access(
    owner: str,
    name: str,
    write_access: bool = False,
    current_user: Optional[UserDTO] = Depends(get_current_user_optional),
    repository_service: RepositoryService = Depends(get_repository_service)
) -> bool:
    """Check if current user has access to repository."""
    # Get repository
    result = await repository_service.get_repository(
        owner,
        name,
        current_user.id if current_user else None
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )
    
    repo = result.value
    
    # Public repositories allow read access
    if not write_access and not repo.is_private:
        return True
    
    # Private repositories or write access require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Owner always has access
    if repo.owner.id == current_user.id:
        return True
    
    # Check repository permissions
    # TODO: Implement collaborator access check
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied"
    )