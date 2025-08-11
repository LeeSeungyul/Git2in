"""Authorization models and permission matrix"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.auth.models import TokenScope


class ResourceType(str, Enum):
    """Types of resources that can be authorized"""

    NAMESPACE = "namespace"
    REPOSITORY = "repository"
    USER = "user"
    TOKEN = "token"
    SYSTEM = "system"


class Action(str, Enum):
    """Actions that can be performed on resources"""

    # Repository actions
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

    # Namespace actions
    CREATE_REPO = "create_repo"
    DELETE_REPO = "delete_repo"
    LIST_REPOS = "list_repos"
    MANAGE_USERS = "manage_users"

    # User actions
    VIEW_USER = "view_user"
    EDIT_USER = "edit_user"
    DELETE_USER = "delete_user"

    # Token actions
    CREATE_TOKEN = "create_token"
    REVOKE_TOKEN = "revoke_token"
    LIST_TOKENS = "list_tokens"

    # System actions
    VIEW_METRICS = "view_metrics"
    VIEW_LOGS = "view_logs"
    MANAGE_SYSTEM = "manage_system"


class Permission(BaseModel):
    """A single permission definition"""

    resource_type: ResourceType
    action: Action
    resource_id: Optional[str] = Field(
        None, description="Specific resource ID or wildcard"
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict, description="Additional conditions"
    )

    def matches(
        self,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if this permission matches the requested access"""
        # Check resource type
        if self.resource_type != resource_type:
            return False

        # Check action
        if self.action != action:
            return False

        # Check resource ID (None or * means all)
        if self.resource_id and self.resource_id != "*":
            if resource_id != self.resource_id:
                return False

        return True

    def to_string(self) -> str:
        """Convert permission to string representation"""
        resource_id = self.resource_id or "*"
        return f"{self.resource_type.value}:{resource_id}:{self.action.value}"

    @classmethod
    def from_string(cls, perm_str: str) -> "Permission":
        """Parse permission from string"""
        parts = perm_str.split(":")
        if len(parts) != 3:
            raise ValueError(f"Invalid permission string: {perm_str}")

        resource_type, resource_id, action = parts
        return cls(
            resource_type=ResourceType(resource_type),
            action=Action(action),
            resource_id=resource_id if resource_id != "*" else None,
        )

    def __hash__(self):
        """Make Permission hashable for use in sets"""
        # Use tuple of immutable attributes
        return hash((self.resource_type, self.action, self.resource_id))

    def __eq__(self, other):
        """Equality comparison for Permission"""
        if not isinstance(other, Permission):
            return False
        return (
            self.resource_type == other.resource_type
            and self.action == other.action
            and self.resource_id == other.resource_id
        )


class Role(str, Enum):
    """Pre-defined roles with permission sets"""

    OWNER = "owner"  # Full control
    MAINTAINER = "maintainer"  # Can manage repos and users
    DEVELOPER = "developer"  # Can read/write repos
    VIEWER = "viewer"  # Read-only access
    GUEST = "guest"  # Minimal access


class RolePermissions(BaseModel):
    """Defines permissions for a role"""

    role: Role
    permissions: List[Permission]
    description: str = ""

    @classmethod
    def get_default_permissions(cls, role: Role) -> List[Permission]:
        """Get default permissions for a role"""
        if role == Role.OWNER:
            return [
                # Full namespace control
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.CREATE_REPO
                ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.DELETE_REPO
                ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.LIST_REPOS
                ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.MANAGE_USERS
                ),
                # Full repository control
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.WRITE),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.DELETE),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.ADMIN),
                # User management
                Permission(resource_type=ResourceType.USER, action=Action.VIEW_USER),
                Permission(resource_type=ResourceType.USER, action=Action.EDIT_USER),
                Permission(resource_type=ResourceType.USER, action=Action.DELETE_USER),
                # Token management
                Permission(
                    resource_type=ResourceType.TOKEN, action=Action.CREATE_TOKEN
                ),
                Permission(
                    resource_type=ResourceType.TOKEN, action=Action.REVOKE_TOKEN
                ),
                Permission(resource_type=ResourceType.TOKEN, action=Action.LIST_TOKENS),
            ]
        elif role == Role.MAINTAINER:
            return [
                # Namespace management
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.CREATE_REPO
                ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.LIST_REPOS
                ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.MANAGE_USERS
                ),
                # Repository control (no delete)
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.WRITE),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.ADMIN),
                # Limited user management
                Permission(resource_type=ResourceType.USER, action=Action.VIEW_USER),
                Permission(resource_type=ResourceType.USER, action=Action.EDIT_USER),
                # Token management
                Permission(
                    resource_type=ResourceType.TOKEN, action=Action.CREATE_TOKEN
                ),
                Permission(
                    resource_type=ResourceType.TOKEN, action=Action.REVOKE_TOKEN
                ),
            ]
        elif role == Role.DEVELOPER:
            return [
                # Repository read/write
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.WRITE),
                # View permissions
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.LIST_REPOS
                ),
                Permission(resource_type=ResourceType.USER, action=Action.VIEW_USER),
                # Own token management
                Permission(
                    resource_type=ResourceType.TOKEN, action=Action.CREATE_TOKEN
                ),
            ]
        elif role == Role.VIEWER:
            return [
                # Read-only access
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
                Permission(
                    resource_type=ResourceType.NAMESPACE, action=Action.LIST_REPOS
                ),
                Permission(resource_type=ResourceType.USER, action=Action.VIEW_USER),
            ]
        else:  # GUEST
            return [
                # Minimal access
                Permission(resource_type=ResourceType.REPOSITORY, action=Action.READ),
            ]


class PermissionGrant(BaseModel):
    """A grant of permissions to a user or token"""

    grantee_id: str = Field(..., description="User ID or token ID")
    grantee_type: str = Field(..., description="'user' or 'token'")
    resource_type: ResourceType
    resource_id: str = Field(..., description="Specific resource or * for all")
    permissions: List[Permission]
    role: Optional[Role] = None
    granted_by: str = Field(..., description="User who granted the permission")
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Check if grant has expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() >= self.expires_at

    def has_permission(self, action: Action, resource_id: Optional[str] = None) -> bool:
        """Check if grant includes specific permission"""
        for perm in self.permissions:
            if perm.matches(self.resource_type, action, resource_id):
                return True
        return False


class PermissionMatrix(BaseModel):
    """Complete permission matrix for the system"""

    grants: List[PermissionGrant] = Field(default_factory=list)
    role_definitions: Dict[Role, RolePermissions] = Field(default_factory=dict)

    def __init__(self, **data):
        super().__init__(**data)
        # Initialize default role definitions if not provided
        if not self.role_definitions:
            for role in Role:
                self.role_definitions[role] = RolePermissions(
                    role=role,
                    permissions=RolePermissions.get_default_permissions(role),
                    description=f"Default {role.value} role",
                )

    def add_grant(self, grant: PermissionGrant) -> None:
        """Add a permission grant"""
        # Remove expired grants for the same grantee/resource
        self.grants = [
            g
            for g in self.grants
            if not (
                g.grantee_id == grant.grantee_id
                and g.resource_type == grant.resource_type
                and g.resource_id == grant.resource_id
            )
            and not g.is_expired()
        ]
        self.grants.append(grant)

    def remove_grant(
        self, grantee_id: str, resource_type: ResourceType, resource_id: str
    ) -> bool:
        """Remove a permission grant"""
        original_count = len(self.grants)
        self.grants = [
            g
            for g in self.grants
            if not (
                g.grantee_id == grantee_id
                and g.resource_type == resource_type
                and g.resource_id == resource_id
            )
        ]
        return len(self.grants) < original_count

    def get_user_permissions(
        self,
        user_id: str,
        resource_type: ResourceType,
        resource_id: Optional[str] = None,
    ) -> Set[Permission]:
        """Get all permissions for a user on a resource"""
        permissions = set()

        for grant in self.grants:
            # Skip expired grants
            if grant.is_expired():
                continue

            # Check if grant applies to this user
            if grant.grantee_id != user_id or grant.grantee_type != "user":
                continue

            # Check if grant applies to this resource
            if grant.resource_type != resource_type:
                continue

            # Check resource ID match
            if grant.resource_id == "*" or grant.resource_id == resource_id:
                permissions.update(grant.permissions)

        return permissions

    def check_permission(
        self,
        user_id: str,
        resource_type: ResourceType,
        action: Action,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if user has specific permission"""
        permissions = self.get_user_permissions(user_id, resource_type, resource_id)

        for perm in permissions:
            if perm.matches(resource_type, action, resource_id):
                return True

        return False

    def grant_role(
        self,
        user_id: str,
        role: Role,
        resource_type: ResourceType,
        resource_id: str,
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> PermissionGrant:
        """Grant a role to a user"""
        # Get role permissions
        role_perms = self.role_definitions[role]

        # Create grant
        grant = PermissionGrant(
            grantee_id=user_id,
            grantee_type="user",
            resource_type=resource_type,
            resource_id=resource_id,
            permissions=role_perms.permissions,
            role=role,
            granted_by=granted_by,
            expires_at=expires_at,
        )

        self.add_grant(grant)
        return grant


class AuthorizationRequest(BaseModel):
    """Request for authorization check"""

    user_id: str
    resource_type: ResourceType
    action: Action
    resource_id: Optional[str] = None
    token_scopes: List[TokenScope] = Field(default_factory=list)
    ip_address: Optional[str] = None
    correlation_id: Optional[str] = None


class AuthorizationResult(BaseModel):
    """Result of authorization check"""

    allowed: bool
    reason: Optional[str] = None
    granted_permissions: List[Permission] = Field(default_factory=list)
    denied_permissions: List[Permission] = Field(default_factory=list)
    applied_rules: List[str] = Field(default_factory=list)

    @classmethod
    def allow(
        cls, reason: str = "Access granted", permissions: List[Permission] = None
    ) -> "AuthorizationResult":
        """Create an allowed result"""
        return cls(allowed=True, reason=reason, granted_permissions=permissions or [])

    @classmethod
    def deny(
        cls, reason: str = "Access denied", denied_permissions: List[Permission] = None
    ) -> "AuthorizationResult":
        """Create a denied result"""
        return cls(
            allowed=False, reason=reason, denied_permissions=denied_permissions or []
        )


class PermissionInheritance(BaseModel):
    """Defines permission inheritance rules"""

    parent_resource_type: ResourceType
    child_resource_type: ResourceType
    inherited_actions: List[Action]

    @classmethod
    def default_rules(cls) -> List["PermissionInheritance"]:
        """Get default inheritance rules"""
        return [
            # Namespace permissions inherit to repositories
            cls(
                parent_resource_type=ResourceType.NAMESPACE,
                child_resource_type=ResourceType.REPOSITORY,
                inherited_actions=[Action.READ, Action.WRITE, Action.ADMIN],
            ),
            # System permissions inherit to everything
            cls(
                parent_resource_type=ResourceType.SYSTEM,
                child_resource_type=ResourceType.NAMESPACE,
                inherited_actions=[
                    Action.READ,
                    Action.WRITE,
                    Action.ADMIN,
                    Action.DELETE,
                ],
            ),
            cls(
                parent_resource_type=ResourceType.SYSTEM,
                child_resource_type=ResourceType.REPOSITORY,
                inherited_actions=[
                    Action.READ,
                    Action.WRITE,
                    Action.ADMIN,
                    Action.DELETE,
                ],
            ),
        ]
