"""Personal Access Token generation module - handles PAT generation only"""

import secrets
import hashlib
from typing import Tuple
from datetime import datetime


class PersonalAccessTokenGenerator:
    """Handles Personal Access Token generation only"""
    
    TOKEN_PREFIX = "git2in_pat_"
    TOKEN_BYTES = 32  # 256 bits of entropy
    
    def generate_token(self) -> Tuple[str, str]:
        """
        Generate a new personal access token
        
        Returns:
            Tuple of (token, token_hash)
            - token: The actual token to give to user (shown once)
            - token_hash: The hash to store in database
        """
        # Generate cryptographically secure random bytes
        random_bytes = secrets.token_urlsafe(self.TOKEN_BYTES)
        
        # Create the full token
        token = f"{self.TOKEN_PREFIX}{random_bytes}"
        
        # Create hash for storage
        token_hash = self._hash_token(token)
        
        return token, token_hash
    
    def hash_token(self, token: str) -> str:
        """
        Hash an existing token for comparison
        
        Args:
            token: The token to hash
            
        Returns:
            The SHA-256 hash of the token
        """
        return self._hash_token(token)
    
    def _hash_token(self, token: str) -> str:
        """Internal method to hash tokens"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def validate_token_format(self, token: str) -> bool:
        """
        Check if token has valid format
        
        Args:
            token: The token to validate
            
        Returns:
            True if format is valid
        """
        if not token or not isinstance(token, str):
            return False
            
        if not token.startswith(self.TOKEN_PREFIX):
            return False
            
        # Check if token has expected length
        suffix = token[len(self.TOKEN_PREFIX):]
        expected_length = (self.TOKEN_BYTES * 4) // 3  # Base64 encoding ratio
        
        return len(suffix) >= expected_length - 2  # Allow for padding variation