"""Base exception classes for Git2in"""

from typing import List, Optional, Dict, Any

class Git2inError(Exception):
    """Base exception for all Git2in errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

class ValidationError(Git2inError):
    """Raised when validation fails"""
    
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(
            f"Validation failed: {', '.join(errors)}",
            {"errors": errors}
        )

class ConfigurationError(Git2inError):
    """Raised when configuration is invalid"""
    pass

class NotFoundError(Git2inError):
    """Base class for not found errors"""
    
    def __init__(self, resource_type: str, resource_id: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(
            f"{resource_type} not found: {resource_id}",
            {
                "resource_type": resource_type,
                "resource_id": resource_id
            }
        )

class RepositoryNotFoundError(NotFoundError):
    """Raised when repository doesn't exist"""
    
    def __init__(self, repo_id: str):
        super().__init__("Repository", repo_id)

class UserNotFoundError(NotFoundError):
    """Raised when user doesn't exist"""
    
    def __init__(self, user_id: str):
        super().__init__("User", user_id)

class GitOperationError(Git2inError):
    """Raised when git operation fails"""
    
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        self.reason = reason
        super().__init__(
            f"Git operation '{operation}' failed: {reason}",
            {
                "operation": operation,
                "reason": reason
            }
        )

class AuthenticationError(Git2inError):
    """Raised when authentication fails"""
    pass

class AuthorizationError(Git2inError):
    """Raised when authorization fails"""
    pass

class ConflictError(Git2inError):
    """Raised when resource already exists"""
    
    def __init__(self, resource_type: str, resource_id: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(
            f"{resource_type} already exists: {resource_id}",
            {
                "resource_type": resource_type,
                "resource_id": resource_id
            }
        )