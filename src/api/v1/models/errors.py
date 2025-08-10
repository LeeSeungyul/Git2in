"""Error response models and exceptions"""

from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ErrorCode(str, Enum):
    """Standardized error codes"""
    
    # Client errors (4xx)
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    CONFLICT = "CONFLICT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    
    # Server errors (5xx)
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    GATEWAY_TIMEOUT = "GATEWAY_TIMEOUT"
    
    # Business logic errors
    INVALID_STATE = "INVALID_STATE"
    OPERATION_FAILED = "OPERATION_FAILED"
    DEPENDENCY_ERROR = "DEPENDENCY_ERROR"
    RESOURCE_LOCKED = "RESOURCE_LOCKED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"


class ErrorDetail(BaseModel):
    """Detailed error information"""
    
    field: Optional[str] = Field(None, description="Field that caused the error")
    message: str = Field(..., description="Error message")
    code: Optional[str] = Field(None, description="Specific error code")
    value: Optional[Any] = Field(None, description="Invalid value that caused the error")


class ErrorResponse(BaseModel):
    """Standardized error response"""
    
    success: bool = Field(False, description="Always false for errors")
    error: ErrorCode = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[List[ErrorDetail]] = Field(None, description="Detailed error information")
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    path: Optional[str] = Field(None, description="Request path")
    method: Optional[str] = Field(None, description="HTTP method")
    
    @classmethod
    def from_validation_error(
        cls,
        errors: List[Dict[str, Any]],
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create error response from validation errors"""
        details = []
        for error in errors:
            loc = error.get("loc", [])
            field = ".".join(str(x) for x in loc[1:]) if len(loc) > 1 else None
            details.append(ErrorDetail(
                field=field,
                message=error.get("msg", "Validation error"),
                code=error.get("type", "validation_error"),
                value=error.get("input")
            ))
        
        return cls(
            error=ErrorCode.VALIDATION_ERROR,
            message="Request validation failed",
            details=details,
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def not_found(
        cls,
        resource: str,
        resource_id: str,
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create not found error response"""
        return cls(
            error=ErrorCode.NOT_FOUND,
            message=f"{resource} with ID '{resource_id}' not found",
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def unauthorized(
        cls,
        message: str = "Authentication required",
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create unauthorized error response"""
        return cls(
            error=ErrorCode.UNAUTHORIZED,
            message=message,
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def forbidden(
        cls,
        message: str = "Access denied",
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create forbidden error response"""
        return cls(
            error=ErrorCode.FORBIDDEN,
            message=message,
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def conflict(
        cls,
        message: str,
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create conflict error response"""
        return cls(
            error=ErrorCode.CONFLICT,
            message=message,
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def rate_limit_exceeded(
        cls,
        retry_after: int,
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create rate limit exceeded error response"""
        return cls(
            error=ErrorCode.RATE_LIMIT_EXCEEDED,
            message=f"Rate limit exceeded. Retry after {retry_after} seconds",
            details=[ErrorDetail(
                field="retry_after",
                message=str(retry_after),
                code="retry_after_seconds"
            )],
            correlation_id=correlation_id,
            path=path,
            method=method
        )
    
    @classmethod
    def internal_error(
        cls,
        message: str = "An internal error occurred",
        correlation_id: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ) -> "ErrorResponse":
        """Create internal error response"""
        return cls(
            error=ErrorCode.INTERNAL_ERROR,
            message=message,
            correlation_id=correlation_id,
            path=path,
            method=method
        )