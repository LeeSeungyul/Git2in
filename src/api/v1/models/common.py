"""Common API models and schemas"""

from typing import Optional, Any, Dict, List, Generic, TypeVar
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from uuid import UUID

T = TypeVar('T')


class BaseResponse(BaseModel):
    """Base response model with common fields"""
    
    success: bool = Field(default=True, description="Whether the request was successful")
    message: Optional[str] = Field(None, description="Optional message")
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class DataResponse(BaseResponse, Generic[T]):
    """Response with data payload"""
    
    data: T = Field(..., description="Response data")


class ListResponse(BaseResponse, Generic[T]):
    """Response with list of items"""
    
    items: List[T] = Field(default_factory=list, description="List of items")
    total: int = Field(0, description="Total number of items")
    page: int = Field(1, description="Current page number")
    per_page: int = Field(20, description="Items per page")
    pages: int = Field(1, description="Total number of pages")
    
    @property
    def has_next(self) -> bool:
        """Check if there's a next page"""
        return self.page < self.pages
    
    @property
    def has_prev(self) -> bool:
        """Check if there's a previous page"""
        return self.page > 1


class ResourceCreatedResponse(BaseResponse):
    """Response for resource creation"""
    
    id: str = Field(..., description="Created resource ID")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    location: Optional[str] = Field(None, description="Resource location URL")


class ResourceUpdatedResponse(BaseResponse):
    """Response for resource update"""
    
    id: str = Field(..., description="Updated resource ID")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Update timestamp")


class ResourceDeletedResponse(BaseResponse):
    """Response for resource deletion"""
    
    id: str = Field(..., description="Deleted resource ID")
    deleted_at: datetime = Field(default_factory=datetime.utcnow, description="Deletion timestamp")


class BulkOperationResponse(BaseResponse):
    """Response for bulk operations"""
    
    total: int = Field(..., description="Total items to process")
    succeeded: int = Field(0, description="Number of successful operations")
    failed: int = Field(0, description="Number of failed operations")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="List of errors")


class HealthStatus(BaseModel):
    """Health check status"""
    
    service: str = Field(..., description="Service name")
    status: str = Field(..., description="Health status")
    version: str = Field(..., description="Service version")
    uptime: float = Field(..., description="Service uptime in seconds")
    
    model_config = ConfigDict(from_attributes=True)