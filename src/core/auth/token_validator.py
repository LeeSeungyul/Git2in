"""JWT token validation module - handles JWT token validation only"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from jose import jwt
from dataclasses import dataclass
from uuid import UUID


@dataclass
class TokenPayload:
    """Validated token payload"""
    user_id: UUID
    username: Optional[str]
    token_type: str
    issued_at: datetime
    expires_at: datetime


class TokenValidator:
    """Handles JWT token validation only"""
    
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        if not secret_key:
            raise ValueError("Secret key is required")
        self._secret_key = secret_key
        self._algorithm = algorithm
    
    def validate_token(self, token: str) -> Optional[TokenPayload]:
        """
        Validate and decode a JWT token
        
        Args:
            token: The token to validate
            
        Returns:
            TokenPayload if valid, None otherwise
        """
        try:
            # Decode with verification
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm]
            )
            
            # Extract required fields
            user_id = UUID(payload.get("sub"))
            username = payload.get("username")
            token_type = payload.get("type", "access")
            issued_at = datetime.fromtimestamp(payload.get("iat"), timezone.utc)
            expires_at = datetime.fromtimestamp(payload.get("exp"), timezone.utc)
            
            # Check if expired
            if expires_at <= datetime.now(timezone.utc):
                return None
            
            return TokenPayload(
                user_id=user_id,
                username=username,
                token_type=token_type,
                issued_at=issued_at,
                expires_at=expires_at
            )
            
        except (jwt.JWTError, ValueError, KeyError):
            return None
    
    def is_token_expired(self, token_payload: TokenPayload) -> bool:
        """
        Check if token is expired
        
        Args:
            token_payload: The validated token payload
            
        Returns:
            True if expired
        """
        return token_payload.expires_at <= datetime.now(timezone.utc)