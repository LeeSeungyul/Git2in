"""Namespace service for business logic"""

from typing import List, Optional, Tuple
from uuid import UUID
from datetime import datetime

from src.core.models.namespace import Namespace
from src.api.v1.models.namespace import NamespaceFilterParams
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class NamespaceService:
    """Service for namespace operations"""
    
    def __init__(self):
        # In-memory storage for now (would be database in production)
        self._namespaces: dict[UUID, Namespace] = {}
        self._name_index: dict[str, UUID] = {}
    
    async def create_namespace(self, namespace: Namespace) -> Namespace:
        """Create a new namespace"""
        if namespace.name in self._name_index:
            raise ValueError(f"Namespace '{namespace.name}' already exists")
        
        self._namespaces[namespace.id] = namespace
        self._name_index[namespace.name] = namespace.id
        
        logger.info(
            "namespace_created",
            namespace_id=str(namespace.id),
            namespace_name=namespace.name
        )
        
        return namespace
    
    async def get_namespace(
        self, 
        namespace_id: UUID,
        user_id: Optional[UUID] = None
    ) -> Optional[Namespace]:
        """Get namespace by ID"""
        namespace = self._namespaces.get(namespace_id)
        
        if namespace and namespace.visibility == "private":
            # Check if user has access to private namespace
            if not user_id or namespace.owner_id != user_id:
                return None
        
        return namespace
    
    async def get_namespace_by_name(self, name: str) -> Optional[Namespace]:
        """Get namespace by name"""
        namespace_id = self._name_index.get(name)
        if namespace_id:
            return self._namespaces.get(namespace_id)
        return None
    
    async def update_namespace(self, namespace: Namespace) -> Namespace:
        """Update namespace"""
        if namespace.id not in self._namespaces:
            raise ValueError(f"Namespace {namespace.id} not found")
        
        self._namespaces[namespace.id] = namespace
        
        logger.info(
            "namespace_updated",
            namespace_id=str(namespace.id),
            namespace_name=namespace.name
        )
        
        return namespace
    
    async def delete_namespace(
        self, 
        namespace_id: UUID,
        cascade: bool = False
    ) -> bool:
        """Delete namespace"""
        namespace = self._namespaces.get(namespace_id)
        if not namespace:
            return False
        
        # In production, would handle cascade deletion of repositories
        if namespace.repository_count > 0 and not cascade:
            raise ValueError(f"Namespace has {namespace.repository_count} repositories")
        
        del self._namespaces[namespace_id]
        del self._name_index[namespace.name]
        
        logger.info(
            "namespace_deleted",
            namespace_id=str(namespace_id),
            namespace_name=namespace.name,
            cascade=cascade
        )
        
        return True
    
    async def list_namespaces(
        self,
        offset: int = 0,
        limit: int = 20,
        filters: Optional[NamespaceFilterParams] = None,
        sort_by: Optional[str] = None,
        sort_desc: bool = False,
        user_id: Optional[UUID] = None
    ) -> Tuple[List[Namespace], int]:
        """List namespaces with filtering and pagination"""
        
        # Start with all namespaces
        namespaces = list(self._namespaces.values())
        
        # Apply visibility filter for user
        if user_id:
            namespaces = [
                ns for ns in namespaces
                if ns.visibility == "public" or ns.owner_id == user_id
            ]
        else:
            # Anonymous users can only see public namespaces
            namespaces = [ns for ns in namespaces if ns.visibility == "public"]
        
        # Apply filters
        if filters:
            if filters.search:
                search_lower = filters.search.lower()
                namespaces = [
                    ns for ns in namespaces
                    if search_lower in ns.name.lower() or
                    (ns.description and search_lower in ns.description.lower())
                ]
            
            if filters.visibility:
                namespaces = [
                    ns for ns in namespaces
                    if ns.visibility == filters.visibility
                ]
            
            if filters.owner_id:
                namespaces = [
                    ns for ns in namespaces
                    if ns.owner_id == filters.owner_id
                ]
        
        # Apply sorting
        if sort_by:
            reverse = sort_desc
            if sort_by == "name":
                namespaces.sort(key=lambda x: x.name, reverse=reverse)
            elif sort_by == "created_at":
                namespaces.sort(key=lambda x: x.created_at, reverse=reverse)
            elif sort_by == "updated_at":
                namespaces.sort(key=lambda x: x.updated_at, reverse=reverse)
            elif sort_by == "repository_count":
                namespaces.sort(key=lambda x: x.repository_count, reverse=reverse)
        
        # Get total before pagination
        total = len(namespaces)
        
        # Apply pagination
        namespaces = namespaces[offset:offset + limit]
        
        return namespaces, total
    
    async def add_member(
        self,
        namespace_id: UUID,
        user_id: UUID,
        role: str,
        added_by: UUID
    ) -> bool:
        """Add member to namespace"""
        # In production, would store in database
        logger.info(
            "namespace_member_added",
            namespace_id=str(namespace_id),
            user_id=str(user_id),
            role=role,
            added_by=str(added_by)
        )
        return True
    
    async def remove_member(
        self,
        namespace_id: UUID,
        user_id: UUID
    ) -> bool:
        """Remove member from namespace"""
        # In production, would remove from database
        logger.info(
            "namespace_member_removed",
            namespace_id=str(namespace_id),
            user_id=str(user_id)
        )
        return True