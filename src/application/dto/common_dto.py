"""Common DTOs used across the application layer.

This module provides common data transfer objects like Result, PagedResult,
and error codes that are used throughout the application services.
"""

from dataclasses import dataclass, field
from typing import Generic, TypeVar, Optional, List, Any
from enum import Enum

T = TypeVar('T')


class ErrorCode(str, Enum):
    """Standard error codes for service operations."""
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RATE_LIMIT = "RATE_LIMIT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


@dataclass
class Result(Generic[T]):
    """Result wrapper for service operations.
    
    Provides a consistent way to return success/failure from service methods
    along with the result value or error information.
    """
    success: bool
    value: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[ErrorCode] = None
    errors: List[str] = field(default_factory=list)
    
    @classmethod
    def ok(cls, value: T) -> "Result[T]":
        """Create a successful result.
        
        Args:
            value: The successful result value
            
        Returns:
            Successful Result instance
        """
        return cls(success=True, value=value)
    
    @classmethod
    def fail(
        cls,
        error: str,
        error_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        errors: Optional[List[str]] = None
    ) -> "Result[T]":
        """Create a failed result.
        
        Args:
            error: Primary error message
            error_code: Error code for categorization
            errors: Additional error messages (e.g., validation errors)
            
        Returns:
            Failed Result instance
        """
        return cls(
            success=False,
            error=error,
            error_code=error_code,
            errors=errors or []
        )
    
    def unwrap(self) -> T:
        """Get the value if successful, otherwise raise an exception.
        
        Returns:
            The successful value
            
        Raises:
            ValueError: If the result is not successful
        """
        if not self.success:
            raise ValueError(f"Cannot unwrap failed result: {self.error}")
        return self.value
    
    def unwrap_or(self, default: T) -> T:
        """Get the value if successful, otherwise return default.
        
        Args:
            default: Default value to return if not successful
            
        Returns:
            The successful value or default
        """
        return self.value if self.success else default
    
    def map(self, func) -> "Result[Any]":
        """Transform the value if successful.
        
        Args:
            func: Function to transform the value
            
        Returns:
            New Result with transformed value or same error
        """
        if self.success:
            return Result.ok(func(self.value))
        return Result.fail(self.error, self.error_code, self.errors)


@dataclass
class PagedResult(Generic[T]):
    """Paginated result for list operations."""
    items: List[T]
    total: int
    page: int
    per_page: int
    
    @property
    def pages(self) -> int:
        """Calculate total number of pages.
        
        Returns:
            Total number of pages
        """
        return max(1, (self.total + self.per_page - 1) // self.per_page)
    
    @property
    def has_next(self) -> bool:
        """Check if there is a next page.
        
        Returns:
            True if there is a next page
        """
        return self.page < self.pages
    
    @property
    def has_prev(self) -> bool:
        """Check if there is a previous page.
        
        Returns:
            True if there is a previous page
        """
        return self.page > 1
    
    @property
    def next_page(self) -> Optional[int]:
        """Get the next page number.
        
        Returns:
            Next page number or None if on last page
        """
        return self.page + 1 if self.has_next else None
    
    @property
    def prev_page(self) -> Optional[int]:
        """Get the previous page number.
        
        Returns:
            Previous page number or None if on first page
        """
        return self.page - 1 if self.has_prev else None


@dataclass
class PaginationParams:
    """Pagination parameters for list operations."""
    page: int = 1
    per_page: int = 20
    
    def __post_init__(self):
        """Validate pagination parameters."""
        if self.page < 1:
            self.page = 1
        if self.per_page < 1:
            self.per_page = 1
        elif self.per_page > 100:
            self.per_page = 100
    
    @property
    def offset(self) -> int:
        """Calculate offset for database queries.
        
        Returns:
            Offset value
        """
        return (self.page - 1) * self.per_page
    
    @property
    def limit(self) -> int:
        """Get limit for database queries.
        
        Returns:
            Limit value
        """
        return self.per_page