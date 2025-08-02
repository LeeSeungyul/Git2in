"""User creation module - handles user creation logic only"""

from typing import Optional
from datetime import datetime, timezone
from uuid import UUID, uuid4

from src.core.user.user_types import UserData, CreatedUser


class UserCreator:
    """Handles user creation logic only"""
    
    def create_user(self, user_data: UserData) -> CreatedUser:
        """
        Create a new user entity
        
        Args:
            user_data: The validated user data
            
        Returns:
            The created user information
        """
        # Generate new user ID
        user_id = uuid4()
        
        # Set creation timestamp
        created_at = datetime.now(timezone.utc)
        
        # Create user entity
        created_user = CreatedUser(
            id=user_id,
            username=user_data.username,
            email=user_data.email,
            created_at=created_at
        )
        
        return created_user
    
    def prepare_user_data(
        self,
        username: str,
        email: str,
        password_hash: str,
        is_admin: bool = False
    ) -> UserData:
        """
        Prepare user data for creation
        
        Args:
            username: The validated username
            email: The validated email
            password_hash: The hashed password
            is_admin: Whether user should be admin
            
        Returns:
            UserData ready for creation
        """
        # Normalize data
        normalized_username = username.strip()
        normalized_email = email.strip().lower()
        
        return UserData(
            username=normalized_username,
            email=normalized_email,
            password_hash=password_hash,
            is_admin=is_admin
        )