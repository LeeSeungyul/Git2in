"""JWT token generation module - handles JWT token generation only"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from uuid import UUID


class TokenGenerator:
    """Handles JWT token generation only"""
    
    DEFAULT_EXPIRY_HOURS: int = 24
    ALGORITHM: str = "HS256"
    
    def __init__(self, secret_key: str):
        if not secret_key or len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        self._secret_key = secret_key
    
    def generate_access_token(
        self,
        user_id: UUID,
        username: str,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate a JWT access token
        
        Args:
            user_id: The user's ID
            username: The user's username
            expires_delta: Optional custom expiration time
            
        Returns:
            The encoded JWT token
        """
        now = datetime.now(timezone.utc)
        expires_at = now + (
            expires_delta or timedelta(hours=self.DEFAULT_EXPIRY_HOURS)
        )
        
        payload = {
            "sub": str(user_id),  # Subject
            "username": username,
            "iat": now,
            "exp": expires_at,
            "type": "access"
        }
        
        return jwt.encode(
            payload,
            self._secret_key,
            algorithm=self.ALGORITHM
        )
    
    def generate_refresh_token(
        self,
        user_id: UUID,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate a JWT refresh token
        
        Args:
            user_id: The user's ID
            expires_delta: Optional custom expiration time
            
        Returns:
            The encoded JWT refresh token
        """
        now = datetime.now(timezone.utc)
        expires_at = now + (
            expires_delta or timedelta(days=30)
        )
        
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": expires_at,
            "type": "refresh"
        }
        
        return jwt.encode(
            payload,
            self._secret_key,
            algorithm=self.ALGORITHM
        )