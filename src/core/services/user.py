"""User service for business logic"""

from typing import List, Optional, Tuple
from uuid import UUID
from datetime import datetime

from src.core.models.user import User
from src.api.v1.models.user import UserFilterParams
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class UserService:
    """Service for user operations"""
    
    def __init__(self):
        # In-memory storage for now (would be database in production)
        self._users: dict[UUID, User] = {}
        self._username_index: dict[str, UUID] = {}
        self._email_index: dict[str, UUID] = {}
        
        # Create default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user for testing"""
        import bcrypt
        from uuid import uuid4
        
        admin_id = UUID("00000000-0000-0000-0000-000000000000")
        admin = User(
            id=admin_id,
            username="administrator",  # Changed from "admin" to avoid reserved name
            email="admin@example.com",
            password_hash=bcrypt.hashpw("admin".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
            full_name="Administrator",
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self._users[admin_id] = admin
        self._username_index["administrator"] = admin_id
        self._email_index["admin@example.com"] = admin_id
    
    async def create_user(self, user: User) -> User:
        """Create a new user"""
        if user.username in self._username_index:
            raise ValueError(f"Username '{user.username}' already exists")
        if user.email in self._email_index:
            raise ValueError(f"Email '{user.email}' already registered")
        
        self._users[user.id] = user
        self._username_index[user.username] = user.id
        self._email_index[user.email] = user.id
        
        logger.info(
            "user_created",
            user_id=str(user.id),
            username=user.username,
            email=user.email
        )
        
        return user
    
    async def get_user(self, user_id: UUID) -> Optional[User]:
        """Get user by ID"""
        return self._users.get(user_id)
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        user_id = self._username_index.get(username)
        if user_id:
            return self._users.get(user_id)
        return None
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        user_id = self._email_index.get(email)
        if user_id:
            return self._users.get(user_id)
        return None
    
    async def update_user(self, user: User) -> User:
        """Update user"""
        if user.id not in self._users:
            raise ValueError(f"User {user.id} not found")
        
        old_user = self._users[user.id]
        
        # Update indexes if username or email changed
        if old_user.username != user.username:
            del self._username_index[old_user.username]
            self._username_index[user.username] = user.id
        
        if old_user.email != user.email:
            del self._email_index[old_user.email]
            self._email_index[user.email] = user.id
        
        self._users[user.id] = user
        
        logger.info(
            "user_updated",
            user_id=str(user.id),
            username=user.username
        )
        
        return user
    
    async def delete_user(self, user_id: UUID) -> bool:
        """Delete user"""
        user = self._users.get(user_id)
        if not user:
            return False
        
        del self._users[user_id]
        del self._username_index[user.username]
        del self._email_index[user.email]
        
        logger.info(
            "user_deleted",
            user_id=str(user_id),
            username=user.username
        )
        
        return True
    
    async def list_users(
        self,
        offset: int = 0,
        limit: int = 20,
        filters: Optional[UserFilterParams] = None,
        sort_by: Optional[str] = None,
        sort_desc: bool = False
    ) -> Tuple[List[User], int]:
        """List users with filtering and pagination"""
        
        # Start with all users
        users = list(self._users.values())
        
        # Apply filters
        if filters:
            if filters.search:
                search_lower = filters.search.lower()
                users = [
                    u for u in users
                    if search_lower in u.username.lower() or
                    search_lower in u.email.lower() or
                    (u.full_name and search_lower in u.full_name.lower())
                ]
            
            if filters.is_active is not None:
                users = [u for u in users if u.is_active == filters.is_active]
            
            if filters.is_admin is not None:
                users = [u for u in users if u.is_admin == filters.is_admin]
            
            if filters.created_after:
                users = [u for u in users if u.created_at >= filters.created_after]
            
            if filters.created_before:
                users = [u for u in users if u.created_at <= filters.created_before]
        
        # Apply sorting
        if sort_by:
            reverse = sort_desc
            if sort_by == "username":
                users.sort(key=lambda x: x.username, reverse=reverse)
            elif sort_by == "email":
                users.sort(key=lambda x: x.email, reverse=reverse)
            elif sort_by == "created_at":
                users.sort(key=lambda x: x.created_at, reverse=reverse)
            elif sort_by == "updated_at":
                users.sort(key=lambda x: x.updated_at, reverse=reverse)
        
        # Get total before pagination
        total = len(users)
        
        # Apply pagination
        users = users[offset:offset + limit]
        
        return users, total
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        import bcrypt
        
        user = await self.get_user_by_username(username)
        if not user:
            return None
        
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return None
        
        # Update last login
        user.last_login_at = datetime.utcnow()
        await self.update_user(user)
        
        return user