"""FastAPI authentication dependencies and middleware"""

from typing import Annotated, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.core.auth.models import TokenClaims, TokenScope
from src.core.auth.revocation import revocation_manager
from src.core.auth.service import token_service
from src.core.exceptions import AuthenticationError, AuthorizationError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)

# Security scheme for OpenAPI
bearer_scheme = HTTPBearer(
    scheme_name="Bearer",
    description="JWT-like Bearer token authentication",
    auto_error=False,  # We'll handle errors ourselves
)


class TokenExtractor:
    """Extract and validate tokens from requests"""

    @staticmethod
    async def extract_token(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    ) -> Optional[str]:
        """Extract token from Authorization header or query parameters"""

        # Try Authorization header first
        if credentials and credentials.credentials:
            return credentials.credentials

        # Try query parameter (for Git operations that can't use headers)
        token = request.query_params.get("token")
        if token:
            return token

        # Try custom header (backup option)
        token = request.headers.get("X-Auth-Token")
        if token:
            return token

        return None


async def get_current_token(
    token: Optional[str] = Depends(TokenExtractor.extract_token),
) -> TokenClaims:
    """Validate token and return claims"""

    if not token:
        logger.warning("auth_missing_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate token
    result = token_service.validate_token(token)

    if not result.valid or not result.claims:
        logger.warning(
            "auth_invalid_token", error=result.error, error_code=result.error_code
        )

        # Determine status code based on error
        if result.error_code == "TOKEN_EXPIRED":
            status_code = status.HTTP_401_UNAUTHORIZED
            detail = "Token has expired"
        elif result.error_code == "INVALID_SIGNATURE":
            status_code = status.HTTP_401_UNAUTHORIZED
            detail = "Invalid token signature"
        else:
            status_code = status.HTTP_401_UNAUTHORIZED
            detail = result.error or "Invalid token"

        raise HTTPException(
            status_code=status_code,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check revocation
    if await revocation_manager.is_revoked(result.claims.jti):
        logger.warning(
            "auth_revoked_token", token_id=result.claims.jti, user_id=result.claims.sub
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(
        "auth_token_validated",
        token_id=result.claims.jti,
        user_id=result.claims.sub,
        scopes=[s.value for s in result.claims.scopes],
    )

    return result.claims


async def get_optional_token(
    token: Optional[str] = Depends(TokenExtractor.extract_token),
) -> Optional[TokenClaims]:
    """Get token claims if present, otherwise return None"""

    if not token:
        return None

    try:
        return await get_current_token(token)
    except HTTPException:
        return None


class RequireScope:
    """Dependency for requiring specific scopes"""

    def __init__(self, *scopes: TokenScope, require_all: bool = False):
        """
        Initialize scope requirement

        Args:
            scopes: Required scopes
            require_all: If True, all scopes are required. If False, any scope is sufficient.
        """
        self.scopes = list(scopes)
        self.require_all = require_all

    async def __call__(
        self, token_claims: TokenClaims = Depends(get_current_token)
    ) -> TokenClaims:
        """Check if token has required scopes"""

        if self.require_all:
            has_permission = token_claims.has_all_scopes(self.scopes)
            error_detail = f"Token missing required scopes: {', '.join(s.value for s in self.scopes)}"
        else:
            has_permission = token_claims.has_any_scope(self.scopes)
            error_detail = f"Token missing any of required scopes: {', '.join(s.value for s in self.scopes)}"

        if not has_permission:
            logger.warning(
                "auth_insufficient_scope",
                required_scopes=[s.value for s in self.scopes],
                token_scopes=[s.value for s in token_claims.scopes],
                require_all=self.require_all,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=error_detail
            )

        return token_claims


class RequireNamespaceAccess:
    """Dependency for namespace-scoped access control"""

    def __init__(self, scope: TokenScope):
        self.scope = scope

    async def __call__(
        self,
        namespace: str,  # From path parameter
        token_claims: TokenClaims = Depends(get_current_token),
    ) -> TokenClaims:
        """Check if token has access to namespace"""

        # Admin always has access
        if token_claims.has_scope(TokenScope.ADMIN):
            return token_claims

        # Check if token has required scope
        if not token_claims.has_scope(self.scope):
            logger.warning(
                "auth_namespace_access_denied",
                namespace=namespace,
                required_scope=self.scope.value,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions for namespace '{namespace}'",
            )

        # Check if token is scoped to this namespace
        if token_claims.namespace and token_claims.namespace != namespace:
            logger.warning(
                "auth_namespace_mismatch",
                requested_namespace=namespace,
                token_namespace=token_claims.namespace,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token not authorized for namespace '{namespace}'",
            )

        return token_claims


class RequireRepositoryAccess:
    """Dependency for repository-scoped access control"""

    def __init__(self, scope: TokenScope):
        self.scope = scope

    async def __call__(
        self,
        namespace: str,  # From path parameter
        repo_name: str,  # From path parameter
        token_claims: TokenClaims = Depends(get_current_token),
    ) -> TokenClaims:
        """Check if token has access to repository"""

        # Admin always has access
        if token_claims.has_scope(TokenScope.ADMIN):
            return token_claims

        # Check if token has required scope
        if not token_claims.has_scope(self.scope):
            logger.warning(
                "auth_repo_access_denied",
                namespace=namespace,
                repo=repo_name,
                required_scope=self.scope.value,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions for repository '{namespace}/{repo_name}'",
            )

        # Check namespace scope if present
        if token_claims.namespace and token_claims.namespace != namespace:
            logger.warning(
                "auth_repo_namespace_mismatch",
                namespace=namespace,
                repo=repo_name,
                token_namespace=token_claims.namespace,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token not authorized for namespace '{namespace}'",
            )

        # Check repository scope if present
        if token_claims.repository and token_claims.repository != repo_name:
            logger.warning(
                "auth_repo_mismatch",
                namespace=namespace,
                requested_repo=repo_name,
                token_repo=token_claims.repository,
                user_id=token_claims.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token not authorized for repository '{repo_name}'",
            )

        return token_claims


# Convenience dependencies
require_admin = RequireScope(TokenScope.ADMIN)
require_user_read = RequireScope(TokenScope.USER_READ)
require_user_write = RequireScope(TokenScope.USER_WRITE)
require_token_create = RequireScope(TokenScope.TOKEN_CREATE)
require_token_revoke = RequireScope(TokenScope.TOKEN_REVOKE)

# Repository access dependencies
require_repo_read = RequireRepositoryAccess(TokenScope.REPO_READ)
require_repo_write = RequireRepositoryAccess(TokenScope.REPO_WRITE)
require_repo_admin = RequireRepositoryAccess(TokenScope.REPO_ADMIN)

# Namespace access dependencies
require_namespace_read = RequireNamespaceAccess(TokenScope.NAMESPACE_READ)
require_namespace_write = RequireNamespaceAccess(TokenScope.NAMESPACE_WRITE)
require_namespace_admin = RequireNamespaceAccess(TokenScope.NAMESPACE_ADMIN)

# Type hints for better IDE support
CurrentToken = Annotated[TokenClaims, Depends(get_current_token)]
OptionalToken = Annotated[Optional[TokenClaims], Depends(get_optional_token)]
AdminToken = Annotated[TokenClaims, Depends(require_admin)]
