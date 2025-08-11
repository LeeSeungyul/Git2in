"""Pagination models and utilities"""

from math import ceil
from typing import Any, Callable, Generic, List, Optional, TypeVar

from fastapi import Query, Request
from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Pagination parameters for list endpoints"""

    page: int = Field(1, ge=1, description="Page number (1-based)")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")
    offset: Optional[int] = Field(None, ge=0, description="Offset for pagination")
    limit: Optional[int] = Field(
        None, ge=1, le=1000, description="Limit for pagination"
    )

    @field_validator("per_page")
    @classmethod
    def validate_per_page(cls, v: int) -> int:
        """Validate per_page is within bounds"""
        if v > 100:
            return 100
        if v < 1:
            return 1
        return v

    def get_offset(self) -> int:
        """Calculate offset from page number"""
        if self.offset is not None:
            return self.offset
        return (self.page - 1) * self.per_page

    def get_limit(self) -> int:
        """Get limit for query"""
        if self.limit is not None:
            return min(self.limit, 1000)
        return self.per_page


class SortParams(BaseModel):
    """Sorting parameters for list endpoints"""

    sort_by: Optional[str] = Field(None, description="Field to sort by")
    sort_order: str = Field("asc", pattern="^(asc|desc)$", description="Sort order")

    @property
    def is_descending(self) -> bool:
        """Check if sort order is descending"""
        return self.sort_order == "desc"


class FilterParams(BaseModel):
    """Base class for filter parameters"""

    search: Optional[str] = Field(None, description="Search query")
    created_after: Optional[str] = Field(
        None, description="Filter by creation date (ISO 8601)"
    )
    created_before: Optional[str] = Field(
        None, description="Filter by creation date (ISO 8601)"
    )
    updated_after: Optional[str] = Field(
        None, description="Filter by update date (ISO 8601)"
    )
    updated_before: Optional[str] = Field(
        None, description="Filter by update date (ISO 8601)"
    )


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper"""

    items: List[T] = Field(default_factory=list, description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page")
    per_page: int = Field(..., description="Items per page")
    pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Whether there's a next page")
    has_prev: bool = Field(..., description="Whether there's a previous page")
    next_page: Optional[int] = Field(None, description="Next page number")
    prev_page: Optional[int] = Field(None, description="Previous page number")

    @classmethod
    def create(
        cls, items: List[T], total: int, page: int, per_page: int
    ) -> "PaginatedResponse[T]":
        """Create a paginated response"""
        pages = ceil(total / per_page) if per_page > 0 else 1
        has_next = page < pages
        has_prev = page > 1

        return cls(
            items=items,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
            has_next=has_next,
            has_prev=has_prev,
            next_page=page + 1 if has_next else None,
            prev_page=page - 1 if has_prev else None,
        )


def get_pagination_params(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
) -> PaginationParams:
    """Dependency to get pagination parameters"""
    return PaginationParams(page=page, per_page=per_page)


def get_sort_params(
    sort_by: Optional[str] = Query(None, description="Field to sort by"),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort order"),
) -> SortParams:
    """Dependency to get sort parameters"""
    return SortParams(sort_by=sort_by, sort_order=sort_order)


def create_link_header(request: Request, page: int, pages: int, per_page: int) -> str:
    """Create Link header for pagination"""
    base_url = str(request.url).split("?")[0]
    links = []

    # First page
    links.append(f'<{base_url}?page=1&per_page={per_page}>; rel="first"')

    # Last page
    links.append(f'<{base_url}?page={pages}&per_page={per_page}>; rel="last"')

    # Previous page
    if page > 1:
        links.append(f'<{base_url}?page={page-1}&per_page={per_page}>; rel="prev"')

    # Next page
    if page < pages:
        links.append(f'<{base_url}?page={page+1}&per_page={per_page}>; rel="next"')

    return ", ".join(links)


class CursorPaginationParams(BaseModel):
    """Cursor-based pagination parameters"""

    cursor: Optional[str] = Field(None, description="Pagination cursor")
    limit: int = Field(20, ge=1, le=100, description="Number of items to return")

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        """Validate limit is within bounds"""
        if v > 100:
            return 100
        if v < 1:
            return 1
        return v


class CursorPaginatedResponse(BaseModel, Generic[T]):
    """Cursor-based paginated response"""

    items: List[T] = Field(default_factory=list, description="List of items")
    next_cursor: Optional[str] = Field(None, description="Cursor for next page")
    has_more: bool = Field(False, description="Whether there are more items")
