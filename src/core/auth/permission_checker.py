"""Permission checking module - handles permission checking logic only"""

from enum import Enum
from typing import Set, Optional
from uuid import UUID
from dataclasses import dataclass


class Permission(Enum):
    """Repository permissions"""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


@dataclass
class PermissionContext:
    """Context for permission check"""
    user_id: UUID
    repository_id: UUID
    is_admin: bool = False
    is_owner: bool = False


class PermissionChecker:
    """Handles permission checking logic only"""
    
    # Permission hierarchy
    PERMISSION_HIERARCHY = {
        Permission.READ: {Permission.READ},
        Permission.WRITE: {Permission.READ, Permission.WRITE},
        Permission.ADMIN: {Permission.READ, Permission.WRITE, Permission.ADMIN}
    }
    
    def check_permission(
        self,
        context: PermissionContext,
        required_permission: Permission,
        granted_permissions: Set[Permission]
    ) -> bool:
        """
        Check if user has required permission
        
        Args:
            context: The permission context
            required_permission: The permission needed
            granted_permissions: User's granted permissions
            
        Returns:
            True if permission is granted
        """
        # System admins have all permissions
        if context.is_admin:
            return True
        
        # Repository owners have admin permission
        if context.is_owner:
            return True
        
        # Check granted permissions
        for granted in granted_permissions:
            if required_permission in self.PERMISSION_HIERARCHY.get(granted, set()):
                return True
        
        return False
    
    def get_effective_permissions(
        self,
        context: PermissionContext,
        granted_permissions: Set[Permission]
    ) -> Set[Permission]:
        """
        Get all effective permissions for user
        
        Args:
            context: The permission context
            granted_permissions: User's granted permissions
            
        Returns:
            Set of all effective permissions
        """
        effective = set()
        
        # Add all permissions if admin or owner
        if context.is_admin or context.is_owner:
            return {Permission.READ, Permission.WRITE, Permission.ADMIN}
        
        # Expand granted permissions
        for granted in granted_permissions:
            effective.update(self.PERMISSION_HIERARCHY.get(granted, set()))
        
        return effective