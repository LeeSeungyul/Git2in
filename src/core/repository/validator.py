"""Repository name validation only"""
import re
from typing import Set

from .repository_types import ValidationResult


class RepositoryValidator:
    """Handles repository name validation only"""
    
    # Repository name pattern
    REPO_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]*$')
    
    # Reserved repository names
    RESERVED_NAMES: Set[str] = {
        'api', 'admin', 'dashboard', 'settings', 'config',
        'static', 'assets', 'public', 'private', 'system',
        'login', 'logout', 'register', 'oauth', 'auth',
        '.git', 'git', 'svn', 'hg', 'cvs'
    }
    
    # Invalid patterns
    INVALID_PATTERNS = [
        r'\.\.',           # Directory traversal
        r'^\.', r'\.$',    # Starting/ending with dot
        r'^-', r'-$',      # Starting/ending with dash
        r'--',             # Double dash
        r'\.\.', r'__',    # Double dot/underscore
        r'\.git$',         # Ending with .git
        r'[<>:"\\|?*]',    # Invalid characters
    ]
    
    def validate_name(self, name: str) -> ValidationResult:
        """
        Validate repository name
        
        Args:
            name: Repository name to validate
            
        Returns:
            ValidationResult with any errors
        """
        errors = []
        
        if not name:
            errors.append("Repository name is required")
            return ValidationResult(False, errors)
        
        # Length validation
        if len(name) < 1:
            errors.append("Repository name cannot be empty")
        elif len(name) > 255:
            errors.append("Repository name must not exceed 255 characters")
        
        # Pattern validation
        if not self.REPO_NAME_PATTERN.match(name):
            errors.append(
                "Repository name must start with alphanumeric and "
                "contain only letters, numbers, dashes, underscores, and dots"
            )
        
        # Invalid patterns check
        for pattern in self.INVALID_PATTERNS:
            if re.search(pattern, name):
                errors.append(f"Repository name contains invalid pattern: {pattern}")
        
        # Reserved name check
        if name.lower() in self.RESERVED_NAMES:
            errors.append(f"Repository name '{name}' is reserved")
        
        return ValidationResult(len(errors) == 0, errors)
    
    def sanitize_name(self, name: str) -> str:
        """
        Sanitize repository name for safe usage
        
        Args:
            name: Repository name to sanitize
            
        Returns:
            Sanitized name
        """
        # Remove any potentially dangerous characters
        sanitized = re.sub(r'[^a-zA-Z0-9-_.]', '', name)
        
        # Remove leading/trailing special chars
        sanitized = sanitized.strip('-._')
        
        # Replace multiple special chars with single
        sanitized = re.sub(r'[-_.]{2,}', '-', sanitized)
        
        return sanitized