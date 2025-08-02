"""Password hashing module - handles password hashing and verification only"""

from passlib.context import CryptContext
from typing import Final


class PasswordHasher:
    """Handles password hashing and verification only"""
    
    # Use bcrypt with cost factor 12
    BCRYPT_ROUNDS: Final[int] = 12
    
    def __init__(self):
        self._context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=self.BCRYPT_ROUNDS
        )
    
    def hash_password(self, plain_password: str) -> str:
        """
        Hash a plain text password
        
        Args:
            plain_password: The password to hash
            
        Returns:
            The hashed password
            
        Raises:
            ValueError: If password is empty
        """
        if not plain_password:
            raise ValueError("Password cannot be empty")
            
        return self._context.hash(plain_password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            plain_password: The password to verify
            hashed_password: The hash to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        if not plain_password or not hashed_password:
            return False
            
        try:
            return self._context.verify(plain_password, hashed_password)
        except Exception:
            # Handle invalid hash format
            return False
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if password hash needs to be updated
        
        Args:
            hashed_password: The hash to check
            
        Returns:
            True if rehashing is recommended
        """
        return self._context.needs_update(hashed_password)