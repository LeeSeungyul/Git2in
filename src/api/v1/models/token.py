"""Token API models"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from uuid import UUID


class TokenCreateRequest(BaseModel):
    """Request model for creating a token"""
    
    name: str = Field(..., min_length=1, max_length=100, description="Token name")
    scopes: List[str] = Field(default_factory=list, description="Token scopes")
    expires_in_days: int = Field(30, ge=1, le=365, description="Token expiration in days")
    namespace: Optional[str] = Field(None, description="Restrict to namespace")
    repository: Optional[str] = Field(None, description="Restrict to repository")


class TokenResponse(BaseModel):
    """Response model for token"""
    
    id: str = Field(..., description="Token ID")
    name: str = Field(..., description="Token name")
    token: Optional[str] = Field(None, description="Token value (only shown on creation)")
    scopes: List[str] = Field(..., description="Token scopes")
    namespace: Optional[str] = Field(None, description="Namespace restriction")
    repository: Optional[str] = Field(None, description="Repository restriction")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: datetime = Field(..., description="Expiration timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(0, description="Number of times used")
    
    class Config:
        from_attributes = True


class TokenListResponse(BaseModel):
    """Response model for token list (without token values)"""
    
    id: str = Field(..., description="Token ID")
    name: str = Field(..., description="Token name")
    scopes: List[str] = Field(..., description="Token scopes")
    namespace: Optional[str] = Field(None, description="Namespace restriction")
    repository: Optional[str] = Field(None, description="Repository restriction")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: datetime = Field(..., description="Expiration timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(0, description="Number of times used")
    is_expired: bool = Field(False, description="Whether token is expired")
    is_revoked: bool = Field(False, description="Whether token is revoked")


class TokenRotateRequest(BaseModel):
    """Request model for rotating a token"""
    
    expires_in_days: int = Field(30, ge=1, le=365, description="New token expiration in days")


class TokenStatistics(BaseModel):
    """Token usage statistics"""
    
    total_tokens: int = Field(0, description="Total number of tokens")
    active_tokens: int = Field(0, description="Number of active tokens")
    expired_tokens: int = Field(0, description="Number of expired tokens")
    revoked_tokens: int = Field(0, description="Number of revoked tokens")
    tokens_by_scope: Dict[str, int] = Field(default_factory=dict, description="Token count by scope")
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list, description="Recent token activity")