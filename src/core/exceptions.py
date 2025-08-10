from typing import Optional, Dict, Any
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    correlation_id: Optional[str] = None


class BaseAPIException(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        details: Optional[Dict[str, Any]] = None
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)
    
    def to_error_response(self, correlation_id: Optional[str] = None) -> ErrorResponse:
        return ErrorResponse(
            code=self.code,
            message=self.message,
            details=self.details,
            correlation_id=correlation_id
        )


class ValidationError(BaseAPIException):
    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-400",
            message=message,
            status_code=400,
            details=details
        )


class AuthenticationError(BaseAPIException):
    def __init__(self, message: str = "Authentication required", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-401",
            message=message,
            status_code=401,
            details=details
        )


class AuthorizationError(BaseAPIException):
    def __init__(self, message: str = "Access denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-403",
            message=message,
            status_code=403,
            details=details
        )


class NotFoundError(BaseAPIException):
    def __init__(self, resource: str = "Resource", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-404",
            message=f"{resource} not found",
            status_code=404,
            details=details
        )


class ConflictError(BaseAPIException):
    def __init__(self, message: str = "Resource conflict", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-409",
            message=message,
            status_code=409,
            details=details
        )


class PayloadTooLargeError(BaseAPIException):
    def __init__(self, message: str = "Payload too large", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-413",
            message=message,
            status_code=413,
            details=details
        )


class RateLimitError(BaseAPIException):
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-429",
            message=message,
            status_code=429,
            details=details
        )


class InternalServerError(BaseAPIException):
    def __init__(self, message: str = "Internal server error", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            code="G2IN-500",
            message=message,
            status_code=500,
            details=details
        )


ERROR_CODES = {
    "G2IN-400": "Bad Request - The request was invalid or malformed",
    "G2IN-401": "Unauthorized - Authentication is required",
    "G2IN-403": "Forbidden - Access to this resource is denied",
    "G2IN-404": "Not Found - The requested resource does not exist",
    "G2IN-409": "Conflict - The request conflicts with existing resources",
    "G2IN-413": "Payload Too Large - The request payload exceeds size limits",
    "G2IN-429": "Too Many Requests - Rate limit has been exceeded",
    "G2IN-500": "Internal Server Error - An unexpected error occurred"
}