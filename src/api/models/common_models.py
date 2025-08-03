"""Common request/response models for the API."""

from datetime import datetime
from typing import Dict, Any, Optional, List, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

T = TypeVar('T')


class ErrorResponse(BaseModel):
    """Standard error response format."""
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    request_id: Optional[UUID] = Field(None, description="Request tracking ID")

    class Config:
        json_schema_extra = {
            "example": {
                "error": "VALIDATION_ERROR",
                "message": "Invalid input data",
                "details": {
                    "field": "username",
                    "reason": "Username already exists"
                },
                "timestamp": "2024-01-20T10:30:00Z",
                "request_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class PaginationParams(BaseModel):
    """Pagination request parameters."""
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")


class PaginationMetadata(BaseModel):
    """Pagination metadata for responses."""
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    total: int = Field(..., description="Total number of items")
    pages: int = Field(..., description="Total number of pages")
    
    @classmethod
    def from_params(cls, params: PaginationParams, total: int) -> "PaginationMetadata":
        """Create pagination metadata from parameters and total count."""
        pages = max(1, (total + params.per_page - 1) // params.per_page)
        return cls(
            page=params.page,
            per_page=params.per_page,
            total=total,
            pages=pages
        )


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""
    items: List[T] = Field(..., description="List of items")
    pagination: PaginationMetadata = Field(..., description="Pagination information")
    
    @classmethod
    def create(
        cls,
        items: List[T],
        params: PaginationParams,
        total: int
    ) -> "PaginatedResponse[T]":
        """Create paginated response from items and parameters."""
        return cls(
            items=items,
            pagination=PaginationMetadata.from_params(params, total)
        )


class HealthStatus(BaseModel):
    """Health check status for a component."""
    status: str = Field(..., description="Component status (healthy/unhealthy)")
    response_time_ms: Optional[int] = Field(None, description="Response time in milliseconds")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional status details")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = Field(..., description="API version")
    checks: Optional[Dict[str, HealthStatus]] = Field(None, description="Individual component checks")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-20T10:30:00Z",
                "version": "1.0.0",
                "checks": {
                    "database": {
                        "status": "healthy",
                        "response_time_ms": 5
                    },
                    "filesystem": {
                        "status": "healthy",
                        "details": {"free_space_gb": 42.5}
                    },
                    "git": {
                        "status": "healthy",
                        "details": {"version": "2.39.0"}
                    }
                }
            }
        }


class ReadinessResponse(BaseModel):
    """Readiness check response."""
    ready: bool = Field(..., description="Whether the service is ready")
    checks: Dict[str, str] = Field(..., description="Status of each dependency")
    
    class Config:
        json_schema_extra = {
            "example": {
                "ready": True,
                "checks": {
                    "database": "ok",
                    "filesystem": "ok",
                    "git": "ok"
                }
            }
        }


class RateLimitInfo(BaseModel):
    """Rate limit information."""
    limit: int = Field(..., description="Request limit")
    remaining: int = Field(..., description="Remaining requests")
    reset: int = Field(..., description="Unix timestamp when limit resets")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retry")


class SortOrder(str):
    """Sort order enumeration."""
    ASC = "asc"
    DESC = "desc"


class BaseFilter(BaseModel):
    """Base filter parameters."""
    sort: Optional[str] = Field(None, description="Sort field")
    order: Optional[SortOrder] = Field(SortOrder.DESC, description="Sort order")
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")
    
    def to_pagination_params(self) -> PaginationParams:
        """Convert to pagination parameters."""
        return PaginationParams(page=self.page, per_page=self.per_page)