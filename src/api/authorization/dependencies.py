"""FastAPI dependencies for authorization"""

from typing import Optional, Callable, Any
from functools import wraps
from fastapi import Depends, HTTPException, status, Request

from src.core.authorization.models import ResourceType, Action, AuthorizationResult
from src.core.authorization.service import authorization_service
from src.core.auth.models import TokenClaims
from src.api.auth.dependencies import get_current_token, get_optional_token
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)


class RequirePermission:
    """Dependency for requiring specific permissions"""
    
    def __init__(
        self,
        resource_type: ResourceType,
        action: Action,
        resource_id_param: Optional[str] = None
    ):
        """
        Initialize permission requirement
        
        Args:
            resource_type: Type of resource being accessed
            action: Action being performed
            resource_id_param: Name of path parameter containing resource ID
        """
        self.resource_type = resource_type
        self.action = action
        self.resource_id_param = resource_id_param
    
    async def __call__(
        self,
        request: Request,
        token_claims: TokenClaims = Depends(get_current_token)
    ) -> AuthorizationResult:
        """Check if token has required permission"""
        
        # Extract resource ID from path parameters if specified
        resource_id = None
        if self.resource_id_param:
            resource_id = request.path_params.get(self.resource_id_param)
        
        # Check permission
        result = authorization_service.check_permission(
            token_claims=token_claims,
            resource_type=self.resource_type,
            action=self.action,
            resource_id=resource_id
        )
        
        if not result.allowed:
            logger.warning(
                "authorization_denied",
                user=token_claims.sub,
                resource_type=self.resource_type.value,
                action=self.action.value,
                resource_id=resource_id,
                reason=result.reason,
                correlation_id=get_correlation_id()
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=result.reason or "Permission denied"
            )
        
        return result


class RequireNamespacePermission:
    """Dependency for namespace-level permissions"""
    
    def __init__(self, action: Action):
        self.action = action
    
    async def __call__(
        self,
        namespace: str,  # From path parameter
        token_claims: TokenClaims = Depends(get_current_token)
    ) -> AuthorizationResult:
        """Check namespace permission"""
        
        result = authorization_service.check_permission(
            token_claims=token_claims,
            resource_type=ResourceType.NAMESPACE,
            action=self.action,
            resource_id=namespace
        )
        
        if not result.allowed:
            logger.warning(
                "namespace_authorization_denied",
                user=token_claims.sub,
                namespace=namespace,
                action=self.action.value,
                reason=result.reason
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied for namespace '{namespace}': {result.reason}"
            )
        
        return result


class RequireRepositoryPermission:
    """Dependency for repository-level permissions"""
    
    def __init__(self, action: Action):
        self.action = action
    
    async def __call__(
        self,
        namespace: str,  # From path parameter
        repo_name: str,  # From path parameter
        token_claims: TokenClaims = Depends(get_current_token)
    ) -> AuthorizationResult:
        """Check repository permission"""
        
        # Clean repo name
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        
        resource_id = f"{namespace}/{repo_name}"
        
        result = authorization_service.check_permission(
            token_claims=token_claims,
            resource_type=ResourceType.REPOSITORY,
            action=self.action,
            resource_id=resource_id
        )
        
        if not result.allowed:
            logger.warning(
                "repository_authorization_denied",
                user=token_claims.sub,
                namespace=namespace,
                repository=repo_name,
                action=self.action.value,
                reason=result.reason
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied for repository '{namespace}/{repo_name}': {result.reason}"
            )
        
        return result


class RequireUserPermission:
    """Dependency for user management permissions"""
    
    def __init__(self, action: Action):
        self.action = action
    
    async def __call__(
        self,
        user_id: str,  # From path parameter
        token_claims: TokenClaims = Depends(get_current_token)
    ) -> AuthorizationResult:
        """Check user management permission"""
        
        # Allow users to manage their own profile for certain actions
        if action in [Action.VIEW_USER, Action.EDIT_USER]:
            if token_claims.sub == user_id or str(token_claims.user_id) == user_id:
                return AuthorizationResult.allow(
                    reason="User can manage own profile"
                )
        
        result = authorization_service.check_permission(
            token_claims=token_claims,
            resource_type=ResourceType.USER,
            action=self.action,
            resource_id=user_id
        )
        
        if not result.allowed:
            logger.warning(
                "user_authorization_denied",
                requesting_user=token_claims.sub,
                target_user=user_id,
                action=self.action.value,
                reason=result.reason
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied for user management: {result.reason}"
            )
        
        return result


def authorize(resource_type: ResourceType, action: Action):
    """Decorator for method-level authorization"""
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract token from kwargs
            token_claims = None
            for key, value in kwargs.items():
                if isinstance(value, TokenClaims):
                    token_claims = value
                    break
            
            if not token_claims:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Extract resource ID if available
            resource_id = kwargs.get("resource_id") or kwargs.get("id")
            
            # Check permission
            result = authorization_service.check_permission(
                token_claims=token_claims,
                resource_type=resource_type,
                action=action,
                resource_id=resource_id
            )
            
            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=result.reason or "Permission denied"
                )
            
            # Add authorization result to kwargs
            kwargs["_auth_result"] = result
            
            # Call original function
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Convenience dependencies for common permissions

# Namespace permissions
require_namespace_create_repo = RequireNamespacePermission(Action.CREATE_REPO)
require_namespace_delete_repo = RequireNamespacePermission(Action.DELETE_REPO)
require_namespace_list_repos = RequireNamespacePermission(Action.LIST_REPOS)
require_namespace_manage_users = RequireNamespacePermission(Action.MANAGE_USERS)

# Repository permissions
require_repo_read = RequireRepositoryPermission(Action.READ)
require_repo_write = RequireRepositoryPermission(Action.WRITE)
require_repo_delete = RequireRepositoryPermission(Action.DELETE)
require_repo_admin = RequireRepositoryPermission(Action.ADMIN)

# User permissions
require_user_view = RequireUserPermission(Action.VIEW_USER)
require_user_edit = RequireUserPermission(Action.EDIT_USER)
require_user_delete = RequireUserPermission(Action.DELETE_USER)

# Token permissions
require_token_create = RequirePermission(ResourceType.TOKEN, Action.CREATE_TOKEN)
require_token_revoke = RequirePermission(ResourceType.TOKEN, Action.REVOKE_TOKEN)
require_token_list = RequirePermission(ResourceType.TOKEN, Action.LIST_TOKENS)

# System permissions
require_view_metrics = RequirePermission(ResourceType.SYSTEM, Action.VIEW_METRICS)
require_view_logs = RequirePermission(ResourceType.SYSTEM, Action.VIEW_LOGS)
require_manage_system = RequirePermission(ResourceType.SYSTEM, Action.MANAGE_SYSTEM)


class AuthorizationContext:
    """Context object for authorization information"""
    
    def __init__(self, result: AuthorizationResult, token_claims: TokenClaims):
        self.result = result
        self.token_claims = token_claims
        self.user_id = token_claims.sub
        self.username = token_claims.username
        self.granted_permissions = result.granted_permissions
    
    def has_permission(self, action: Action) -> bool:
        """Check if context has specific permission"""
        for perm in self.granted_permissions:
            if perm.action == action:
                return True
        return False


async def get_authorization_context(
    request: Request,
    token_claims: TokenClaims = Depends(get_current_token)
) -> AuthorizationContext:
    """Get authorization context for current request"""
    
    # Parse resource from request path
    resource_type, resource_id = authorization_service.parse_resource_path(
        request.url.path
    )
    
    # Determine action from method
    method_action_map = {
        "GET": Action.READ,
        "POST": Action.WRITE,
        "PUT": Action.WRITE,
        "PATCH": Action.WRITE,
        "DELETE": Action.DELETE
    }
    action = method_action_map.get(request.method, Action.READ)
    
    # Check permission
    result = authorization_service.check_permission(
        token_claims=token_claims,
        resource_type=resource_type,
        action=action,
        resource_id=resource_id
    )
    
    return AuthorizationContext(result, token_claims)