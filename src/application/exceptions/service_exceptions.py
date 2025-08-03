"""Service layer exceptions.

This module defines exceptions that are raised by application services
to communicate errors to the API layer.
"""

from typing import Optional, List, Dict, Any
from src.application.dto.common_dto import ErrorCode


class ServiceError(Exception):
    """Base exception for all service layer errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Standardized error code for categorization
        details: Additional error details as key-value pairs
    """
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize service error.
        
        Args:
            message: Error message
            error_code: Error code for categorization
            details: Additional error context
        """
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary representation.
        
        Returns:
            Dictionary with error information
        """
        return {
            "error": self.message,
            "error_code": self.error_code.value,
            "details": self.details
        }


class ValidationError(ServiceError):
    """Raised when input validation fails.
    
    Attributes:
        errors: List of validation error messages
    """
    
    def __init__(self, message: str, errors: List[str]):
        """Initialize validation error.
        
        Args:
            message: Primary error message
            errors: List of specific validation errors
        """
        super().__init__(
            message,
            ErrorCode.VALIDATION_ERROR,
            {"errors": errors}
        )
        self.errors = errors


class NotFoundError(ServiceError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        """Initialize not found error.
        
        Args:
            resource_type: Type of resource (e.g., "User", "Repository")
            resource_id: Identifier of the missing resource
        """
        message = f"{resource_type} not found: {resource_id}"
        super().__init__(
            message,
            ErrorCode.NOT_FOUND,
            {"resource_type": resource_type, "resource_id": resource_id}
        )
        self.resource_type = resource_type
        self.resource_id = resource_id


class ConflictError(ServiceError):
    """Raised when an operation conflicts with existing data."""
    
    def __init__(self, message: str, conflicting_field: Optional[str] = None):
        """Initialize conflict error.
        
        Args:
            message: Error message describing the conflict
            conflicting_field: Field that caused the conflict
        """
        details = {}
        if conflicting_field:
            details["field"] = conflicting_field
        super().__init__(message, ErrorCode.CONFLICT, details)


class AuthenticationError(ServiceError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        """Initialize authentication error.
        
        Args:
            message: Error message
        """
        super().__init__(message, ErrorCode.UNAUTHORIZED)


class AuthorizationError(ServiceError):
    """Raised when authorization fails."""
    
    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: Optional[str] = None
    ):
        """Initialize authorization error.
        
        Args:
            message: Error message
            required_permission: Permission that was required
        """
        details = {}
        if required_permission:
            details["required_permission"] = required_permission
        super().__init__(message, ErrorCode.FORBIDDEN, details)


class RateLimitError(ServiceError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None
    ):
        """Initialize rate limit error.
        
        Args:
            message: Error message
            retry_after: Seconds until the rate limit resets
        """
        details = {}
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, ErrorCode.RATE_LIMIT, details)
        self.retry_after = retry_after


class ServiceUnavailableError(ServiceError):
    """Raised when a required service is unavailable."""
    
    def __init__(self, service_name: str, reason: Optional[str] = None):
        """Initialize service unavailable error.
        
        Args:
            service_name: Name of the unavailable service
            reason: Reason for unavailability
        """
        message = f"Service '{service_name}' is unavailable"
        if reason:
            message += f": {reason}"
        super().__init__(
            message,
            ErrorCode.SERVICE_UNAVAILABLE,
            {"service": service_name, "reason": reason}
        )


class InvalidTokenError(AuthenticationError):
    """Raised when a token is invalid."""
    
    def __init__(self, token_type: str = "access"):
        """Initialize invalid token error.
        
        Args:
            token_type: Type of token that is invalid
        """
        super().__init__(f"Invalid {token_type} token")
        self.details["token_type"] = token_type


class ExpiredTokenError(AuthenticationError):
    """Raised when a token has expired."""
    
    def __init__(self, token_type: str = "access"):
        """Initialize expired token error.
        
        Args:
            token_type: Type of token that expired
        """
        super().__init__(f"{token_type.capitalize()} token has expired")
        self.details["token_type"] = token_type