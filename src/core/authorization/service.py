"""Authorization service for permission checking"""

from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import urlparse
import fnmatch
from functools import lru_cache

from src.core.authorization.models import (
    Permission, Role, ResourceType, Action, PermissionMatrix,
    AuthorizationRequest, AuthorizationResult, PermissionGrant,
    PermissionInheritance
)
from src.core.auth.models import TokenClaims, TokenScope
from src.infrastructure.logging import get_logger
from src.core.exceptions import AuthorizationError

logger = get_logger(__name__)


class AuthorizationService:
    """Core authorization service for permission validation"""
    
    def __init__(self, permission_matrix: Optional[PermissionMatrix] = None):
        self.permission_matrix = permission_matrix or PermissionMatrix()
        self.inheritance_rules = PermissionInheritance.default_rules()
        self._cache: Dict[str, AuthorizationResult] = {}
        self._cache_size = 1000
    
    def check_permission(
        self,
        token_claims: TokenClaims,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str] = None
    ) -> AuthorizationResult:
        """Check if token has permission for requested action"""
        
        # Create cache key
        cache_key = self._make_cache_key(
            token_claims.sub,
            resource_type,
            action,
            resource_id
        )
        
        # Check cache
        if cache_key in self._cache:
            logger.debug(
                "authorization_cache_hit",
                user=token_claims.sub,
                resource_type=resource_type.value,
                action=action.value
            )
            return self._cache[cache_key]
        
        # Perform authorization check
        result = self._perform_authorization(
            token_claims,
            resource_type,
            action,
            resource_id
        )
        
        # Update cache
        self._update_cache(cache_key, result)
        
        # Log result
        logger.info(
            "authorization_check",
            user=token_claims.sub,
            resource_type=resource_type.value,
            action=action.value,
            resource_id=resource_id,
            allowed=result.allowed,
            reason=result.reason
        )
        
        return result
    
    def _perform_authorization(
        self,
        token_claims: TokenClaims,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str] = None
    ) -> AuthorizationResult:
        """Perform the actual authorization check"""
        
        # Check if admin token (bypass all checks)
        if token_claims.has_scope(TokenScope.ADMIN):
            return AuthorizationResult.allow(
                reason="Admin access granted",
                permissions=[Permission(
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id
                )]
            )
        
        # Check namespace/repository restrictions
        if resource_type == ResourceType.REPOSITORY and resource_id:
            # Extract namespace and repo from resource_id (format: namespace/repo)
            parts = resource_id.split("/")
            if len(parts) >= 2:
                namespace = parts[0]
                repo = "/".join(parts[1:])
                
                # Check namespace restriction
                if token_claims.namespace and token_claims.namespace != namespace:
                    return AuthorizationResult.deny(
                        reason="Token not authorized for this namespace"
                    )
                
                # Check repository restriction
                if token_claims.repository and token_claims.repository != repo:
                    return AuthorizationResult.deny(
                        reason="Token not authorized for this repository"
                    )
        
        # Parse token scopes to permissions
        token_permissions = self._parse_token_scopes(
            token_claims.scopes,
            resource_type,
            resource_id
        )
        
        # Check token permissions
        for perm in token_permissions:
            if perm.matches(resource_type, action, resource_id):
                return AuthorizationResult.allow(
                    reason="Permission granted by token scope",
                    permissions=[perm]
                )
        
        # Check matrix permissions for user
        if token_claims.user_id:
            user_permissions = self.permission_matrix.get_user_permissions(
                str(token_claims.user_id),
                resource_type,
                resource_id
            )
            
            for perm in user_permissions:
                if perm.matches(resource_type, action, resource_id):
                    return AuthorizationResult.allow(
                        reason="Permission granted by user role",
                        permissions=[perm]
                    )
        
        # Check inherited permissions
        inherited_perms = self._check_inherited_permissions(
            token_claims,
            resource_type,
            action,
            resource_id
        )
        
        if inherited_perms:
            return AuthorizationResult.allow(
                reason="Permission granted by inheritance",
                permissions=inherited_perms
            )
        
        # Check namespace/repository restrictions in token
        if not self._check_resource_restrictions(token_claims, resource_type, resource_id):
            return AuthorizationResult.deny(
                reason="Token not authorized for this resource",
                denied_permissions=[Permission(
                    resource_type=resource_type,
                    action=action,
                    resource_id=resource_id
                )]
            )
        
        # Default deny
        return AuthorizationResult.deny(
            reason="No matching permissions found",
            denied_permissions=[Permission(
                resource_type=resource_type,
                action=action,
                resource_id=resource_id
            )]
        )
    
    def _parse_token_scopes(
        self,
        scopes: List[TokenScope],
        resource_type: ResourceType,
        resource_id: Optional[str] = None
    ) -> List[Permission]:
        """Parse token scopes into permissions"""
        permissions = []
        
        for scope in scopes:
            # Map token scopes to permissions
            if scope == TokenScope.NAMESPACE_READ:
                if resource_type == ResourceType.NAMESPACE:
                    permissions.append(Permission(
                        resource_type=ResourceType.NAMESPACE,
                        action=Action.LIST_REPOS,
                        resource_id=resource_id
                    ))
            
            elif scope == TokenScope.NAMESPACE_WRITE:
                if resource_type == ResourceType.NAMESPACE:
                    permissions.extend([
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.LIST_REPOS,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.CREATE_REPO,
                            resource_id=resource_id
                        )
                    ])
            
            elif scope == TokenScope.NAMESPACE_ADMIN:
                if resource_type == ResourceType.NAMESPACE:
                    permissions.extend([
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.LIST_REPOS,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.CREATE_REPO,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.DELETE_REPO,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.NAMESPACE,
                            action=Action.MANAGE_USERS,
                            resource_id=resource_id
                        )
                    ])
            
            elif scope == TokenScope.REPO_READ:
                if resource_type == ResourceType.REPOSITORY:
                    permissions.append(Permission(
                        resource_type=ResourceType.REPOSITORY,
                        action=Action.READ,
                        resource_id=resource_id
                    ))
            
            elif scope == TokenScope.REPO_WRITE:
                if resource_type == ResourceType.REPOSITORY:
                    permissions.extend([
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.READ,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.WRITE,
                            resource_id=resource_id
                        )
                    ])
            
            elif scope == TokenScope.REPO_ADMIN:
                if resource_type == ResourceType.REPOSITORY:
                    permissions.extend([
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.READ,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.WRITE,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.ADMIN,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.REPOSITORY,
                            action=Action.DELETE,
                            resource_id=resource_id
                        )
                    ])
            
            elif scope == TokenScope.USER_READ:
                if resource_type == ResourceType.USER:
                    permissions.append(Permission(
                        resource_type=ResourceType.USER,
                        action=Action.VIEW_USER,
                        resource_id=resource_id
                    ))
            
            elif scope == TokenScope.USER_WRITE:
                if resource_type == ResourceType.USER:
                    permissions.extend([
                        Permission(
                            resource_type=ResourceType.USER,
                            action=Action.VIEW_USER,
                            resource_id=resource_id
                        ),
                        Permission(
                            resource_type=ResourceType.USER,
                            action=Action.EDIT_USER,
                            resource_id=resource_id
                        )
                    ])
            
            elif scope == TokenScope.TOKEN_CREATE:
                if resource_type == ResourceType.TOKEN:
                    permissions.append(Permission(
                        resource_type=ResourceType.TOKEN,
                        action=Action.CREATE_TOKEN,
                        resource_id=resource_id
                    ))
            
            elif scope == TokenScope.TOKEN_REVOKE:
                if resource_type == ResourceType.TOKEN:
                    permissions.append(Permission(
                        resource_type=ResourceType.TOKEN,
                        action=Action.REVOKE_TOKEN,
                        resource_id=resource_id
                    ))
        
        return permissions
    
    def _check_inherited_permissions(
        self,
        token_claims: TokenClaims,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str] = None
    ) -> List[Permission]:
        """Check for inherited permissions from parent resources"""
        inherited = []
        
        for rule in self.inheritance_rules:
            if rule.child_resource_type != resource_type:
                continue
            
            if action not in rule.inherited_actions:
                continue
            
            # Check parent permissions
            parent_perms = self._parse_token_scopes(
                token_claims.scopes,
                rule.parent_resource_type,
                None  # Parent resource ID
            )
            
            for perm in parent_perms:
                if perm.action in rule.inherited_actions:
                    inherited.append(Permission(
                        resource_type=resource_type,
                        action=action,
                        resource_id=resource_id
                    ))
                    break
        
        return inherited
    
    def _check_resource_restrictions(
        self,
        token_claims: TokenClaims,
        resource_type: ResourceType,
        resource_id: Optional[str] = None
    ) -> bool:
        """Check if token is restricted to specific resources"""
        
        # Check namespace restriction
        if token_claims.namespace:
            if resource_type == ResourceType.NAMESPACE:
                if resource_id and resource_id != token_claims.namespace:
                    return False
            elif resource_type == ResourceType.REPOSITORY:
                # Parse namespace from repository path
                if resource_id and "/" in resource_id:
                    namespace = resource_id.split("/")[0]
                    if namespace != token_claims.namespace:
                        return False
        
        # Check repository restriction
        if token_claims.repository:
            if resource_type == ResourceType.REPOSITORY:
                if resource_id:
                    # Check if it's the same repository
                    repo_name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
                    if repo_name != token_claims.repository:
                        return False
        
        return True
    
    def parse_resource_path(self, path: str) -> Tuple[ResourceType, Optional[str]]:
        """Parse resource type and ID from request path"""
        
        # Remove leading/trailing slashes
        path = path.strip("/")
        parts = path.split("/")
        
        # Determine resource type based on path structure
        if not parts:
            return ResourceType.SYSTEM, None
        
        # Git endpoints: /git/{namespace}/{repo}/...
        if parts[0] == "git" and len(parts) >= 3:
            namespace = parts[1]
            repo = parts[2].replace(".git", "")
            return ResourceType.REPOSITORY, f"{namespace}/{repo}"
        
        # Namespace endpoints: /namespaces/{namespace}/...
        if parts[0] == "namespaces" and len(parts) >= 2:
            return ResourceType.NAMESPACE, parts[1]
        
        # User endpoints: /users/{user}/...
        if parts[0] == "users" and len(parts) >= 2:
            return ResourceType.USER, parts[1]
        
        # Token endpoints: /auth/...
        if parts[0] == "auth":
            return ResourceType.TOKEN, None
        
        # System endpoints
        if parts[0] in ["metrics", "health", "logs"]:
            return ResourceType.SYSTEM, None
        
        # Default to system
        return ResourceType.SYSTEM, None
    
    def grant_role_to_user(
        self,
        user_id: str,
        role: Role,
        resource_type: ResourceType,
        resource_id: str,
        granted_by: str
    ) -> PermissionGrant:
        """Grant a role to a user"""
        grant = self.permission_matrix.grant_role(
            user_id=user_id,
            role=role,
            resource_type=resource_type,
            resource_id=resource_id,
            granted_by=granted_by
        )
        
        # Clear cache for this user
        self._clear_user_cache(user_id)
        
        logger.info(
            "role_granted",
            user_id=user_id,
            role=role.value,
            resource_type=resource_type.value,
            resource_id=resource_id,
            granted_by=granted_by
        )
        
        return grant
    
    def revoke_user_permissions(
        self,
        user_id: str,
        resource_type: ResourceType,
        resource_id: str
    ) -> bool:
        """Revoke user permissions for a resource"""
        result = self.permission_matrix.remove_grant(
            user_id, resource_type, resource_id
        )
        
        # Clear cache for this user
        self._clear_user_cache(user_id)
        
        if result:
            logger.info(
                "permissions_revoked",
                user_id=user_id,
                resource_type=resource_type.value,
                resource_id=resource_id
            )
        
        return result
    
    def _make_cache_key(
        self,
        user_id: str,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str]
    ) -> str:
        """Create cache key for authorization result"""
        return f"{user_id}:{resource_type.value}:{action.value}:{resource_id or '*'}"
    
    def _update_cache(self, key: str, result: AuthorizationResult) -> None:
        """Update authorization cache"""
        # Simple LRU: if cache is full, remove oldest entries
        if len(self._cache) >= self._cache_size:
            # Remove first 10% of cache
            remove_count = self._cache_size // 10
            for _ in range(remove_count):
                self._cache.pop(next(iter(self._cache)))
        
        self._cache[key] = result
    
    def _clear_user_cache(self, user_id: str) -> None:
        """Clear cache entries for a specific user"""
        keys_to_remove = [
            k for k in self._cache.keys()
            if k.startswith(f"{user_id}:")
        ]
        for key in keys_to_remove:
            del self._cache[key]
    
    def clear_cache(self) -> None:
        """Clear entire authorization cache"""
        self._cache.clear()


# Global authorization service instance
authorization_service = AuthorizationService()