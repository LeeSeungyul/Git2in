"""User input validation module - handles user input validation only"""

import re
from typing import List, Optional

from src.core.user.user_types import ValidationResult


class UserValidator:
    """Handles user input validation only"""
    
    # Validation patterns
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Reserved usernames
    RESERVED_USERNAMES = {
        'admin', 'root', 'administrator', 'system', 'git', 'api',
        'www', 'ftp', 'mail', 'email', 'sa', 'support', 'operator',
        'guest', 'user', 'test', 'demo', 'oracle', 'web', 'www-data'
    }
    
    # Common passwords to reject (top 100)
    COMMON_PASSWORDS = {
        'password', '123456', 'password123', 'admin', 'letmein',
        'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
        'Password1', 'password1', '123456789', 'welcome123',
        '1234567', '12345678', '12345', '1234', 'qwertyuiop',
        'qwerty123', 'qwerty1', 'password1234', 'password12345',
        'password123456', 'admin123', 'root', 'toor', 'pass',
        'test', 'guest', 'master', 'dragon', 'sunshine',
        'ashley', 'bailey', 'shadow', 'superman', 'iloveyou',
        '123123', 'hello', 'charlie', 'aa123456', 'donald',
        'password12', 'qwerty12345', 'admin1234', 'admin12345',
        'passw0rd', 'p@ssw0rd', 'p@ssword', 'P@ssw0rd'
    }
    
    def validate_username(self, username: str) -> ValidationResult:
        """
        Validate username format and availability
        
        Args:
            username: The username to validate
            
        Returns:
            ValidationResult with any errors
        """
        errors = []
        
        if not username:
            errors.append("Username is required")
            return ValidationResult(False, errors)
        
        # Length check
        if len(username) < 3:
            errors.append("Username must be at least 3 characters")
        elif len(username) > 32:
            errors.append("Username must not exceed 32 characters")
        
        # Format check
        if not self.USERNAME_PATTERN.match(username):
            errors.append(
                "Username must start with letter/number and contain "
                "only letters, numbers, underscores, and hyphens"
            )
        
        # Reserved check
        if username.lower() in self.RESERVED_USERNAMES:
            errors.append("Username is reserved and cannot be used")
        
        return ValidationResult(len(errors) == 0, errors)
    
    def validate_email(self, email: str) -> ValidationResult:
        """
        Validate email format
        
        Args:
            email: The email to validate
            
        Returns:
            ValidationResult with any errors
        """
        errors = []
        
        if not email:
            errors.append("Email is required")
            return ValidationResult(False, errors)
        
        # Basic format check
        if not self.EMAIL_PATTERN.match(email):
            errors.append("Invalid email format")
        
        # Length check
        if len(email) > 255:
            errors.append("Email must not exceed 255 characters")
        
        return ValidationResult(len(errors) == 0, errors)
    
    def validate_password(
        self,
        password: str,
        username: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate password strength
        
        Args:
            password: The password to validate
            username: Optional username to check similarity
            
        Returns:
            ValidationResult with any errors
        """
        errors = []
        
        if not password:
            errors.append("Password is required")
            return ValidationResult(False, errors)
        
        # Length check
        if len(password) < 8:
            errors.append("Password must be at least 8 characters")
        elif len(password) > 1024:
            errors.append("Password is too long")
        
        # Common password check
        if password.lower() in self.COMMON_PASSWORDS:
            errors.append("Password is too common")
        
        # Username similarity check
        if username and password.lower() == username.lower():
            errors.append("Password must be different from username")
        
        return ValidationResult(len(errors) == 0, errors)