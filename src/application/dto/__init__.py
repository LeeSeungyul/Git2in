"""Application Data Transfer Objects.

This module contains DTOs used for data transfer between layers
and for API request/response handling.
"""

from src.application.dto.base import BaseDTO, IdentifiableDTO, TimestampedDTO, DTOProtocol
from src.application.dto.common_dto import (
    Result,
    PagedResult,
    PaginationParams,
    ErrorCode
)
from src.application.dto.user_dto import (
    RegisterUserRequest,
    UpdateProfileRequest,
    ChangePasswordRequest,
    UserDTO,
    PublicUserDTO,
    UserSearchResult
)
from src.application.dto.auth_dto import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    TokenPayload,
    CreatePersonalAccessTokenRequest,
    PersonalAccessTokenDTO,
    ValidateTokenRequest,
    TokenValidationResult,
    LogoutRequest,
    SessionInfo
)
from src.application.dto.repository_dto import (
    CreateRepositoryRequest,
    UpdateRepositoryRequest,
    RepositoryDTO,
    RepositoryFilter,
    RepositoryVisibility,
    RepositoryPermission,
    CloneURLs,
    AddCollaboratorRequest,
    RepositoryCollaborator,
    RepositoryStatistics,
    GitRef,
    RepositoryRefs,
    GitServiceType,
    GitOperationRequest,
    RepositoryAccessLog
)

__all__ = [
    # Base DTOs
    "BaseDTO",
    "IdentifiableDTO",
    "TimestampedDTO",
    "DTOProtocol",
    
    # Common DTOs
    "Result",
    "PagedResult",
    "PaginationParams",
    "ErrorCode",
    
    # User DTOs
    "RegisterUserRequest",
    "UpdateProfileRequest",
    "ChangePasswordRequest",
    "UserDTO",
    "PublicUserDTO",
    "UserSearchResult",
    
    # Auth DTOs
    "LoginRequest",
    "TokenResponse",
    "RefreshTokenRequest",
    "TokenPayload",
    "CreatePersonalAccessTokenRequest",
    "PersonalAccessTokenDTO",
    "ValidateTokenRequest",
    "TokenValidationResult",
    "LogoutRequest",
    "SessionInfo",
    
    # Repository DTOs
    "CreateRepositoryRequest",
    "UpdateRepositoryRequest",
    "RepositoryDTO",
    "RepositoryFilter",
    "RepositoryVisibility",
    "RepositoryPermission",
    "CloneURLs",
    "AddCollaboratorRequest",
    "RepositoryCollaborator",
    "RepositoryStatistics",
    "GitRef",
    "RepositoryRefs",
    "GitServiceType",
    "GitOperationRequest",
    "RepositoryAccessLog",
]