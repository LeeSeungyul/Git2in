from datetime import datetime, timedelta
from typing import Optional, List, ClassVar, Set
from uuid import UUID, uuid4
import hashlib
import secrets

from pydantic import BaseModel, Field, field_validator, computed_field, ConfigDict

from src.core.config import settings


class Token(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        json_encoders={datetime: lambda v: v.isoformat()}
    )
    
    token_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique token identifier (JTI)"
    )
    user_id: UUID = Field(
        ...,
        description="UUID of the token owner"
    )
    name: Optional[str] = Field(
        None,
        max_length=128,
        description="Optional token name for identification"
    )
    token_hash: str = Field(
        ...,
        description="SHA256 hash of the actual token"
    )
    scopes: List[str] = Field(
        default_factory=list,
        description="List of token scopes/permissions"
    )
    issued_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Token issuance timestamp"
    )
    expires_at: Optional[datetime] = Field(
        None,
        description="Token expiration timestamp"
    )
    is_revoked: bool = Field(
        default=False,
        description="Whether the token has been revoked"
    )
    revoked_at: Optional[datetime] = Field(
        None,
        description="Timestamp when token was revoked"
    )
    last_used: Optional[datetime] = Field(
        None,
        description="Last time the token was used"
    )
    usage_count: int = Field(
        default=0,
        ge=0,
        description="Number of times token has been used"
    )
    
    # Valid token scopes
    VALID_SCOPES: ClassVar[Set[str]] = {
        "read:repository",      # Read repository contents
        "write:repository",     # Write to repositories
        "admin:repository",     # Full repository administration
        "create:repository",    # Create new repositories
        "delete:repository",    # Delete repositories
        "read:namespace",       # Read namespace info
        "admin:namespace",      # Full namespace administration
        "read:user",           # Read user information
        "write:user",          # Modify user information
        "admin:user",          # User administration
        "read:audit",          # Read audit logs
        "api:full",            # Full API access
    }
    
    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: List[str]) -> List[str]:
        # Remove duplicates
        v = list(set(v))
        
        # If token has api:full, it has all scopes
        if "api:full" in v:
            return ["api:full"]
        
        # Validate each scope
        invalid_scopes = set(v) - cls.VALID_SCOPES
        if invalid_scopes:
            raise ValueError(f"Invalid scopes: {invalid_scopes}")
        
        return sorted(v)
    
    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, v: Optional[datetime], info) -> Optional[datetime]:
        if v is None:
            # Set default expiration based on settings
            issued_at = info.data.get("issued_at", datetime.utcnow())
            expiry_seconds = settings.token_expiry_seconds
            return issued_at + timedelta(seconds=expiry_seconds)
        
        # Ensure expiration is in the future
        if v <= datetime.utcnow():
            raise ValueError("Token expiration must be in the future")
        
        return v
    
    @field_validator("revoked_at")
    @classmethod
    def validate_revoked_at(cls, v: Optional[datetime], info) -> Optional[datetime]:
        is_revoked = info.data.get("is_revoked", False)
        
        if is_revoked and v is None:
            return datetime.utcnow()
        
        if not is_revoked and v is not None:
            raise ValueError("revoked_at can only be set when is_revoked is True")
        
        return v
    
    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check if the token has expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @computed_field
    @property
    def is_valid(self) -> bool:
        """Check if the token is currently valid"""
        return not self.is_revoked and not self.is_expired
    
    @computed_field
    @property
    def time_until_expiry(self) -> Optional[timedelta]:
        """Time remaining until token expires"""
        if self.expires_at is None:
            return None
        
        if self.is_expired:
            return timedelta(0)
        
        return self.expires_at - datetime.utcnow()
    
    @staticmethod
    def generate_token() -> str:
        """Generate a new secure random token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token using SHA256"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope"""
        if "api:full" in self.scopes:
            return True
        return scope in self.scopes
    
    def has_any_scope(self, scopes: List[str]) -> bool:
        """Check if token has any of the specified scopes"""
        if "api:full" in self.scopes:
            return True
        return any(s in self.scopes for s in scopes)
    
    def has_all_scopes(self, scopes: List[str]) -> bool:
        """Check if token has all of the specified scopes"""
        if "api:full" in self.scopes:
            return True
        return all(s in self.scopes for s in scopes)
    
    def record_usage(self) -> None:
        """Record that the token was used"""
        self.last_used = datetime.utcnow()
        self.usage_count += 1
    
    def revoke(self) -> None:
        """Revoke the token"""
        self.is_revoked = True
        self.revoked_at = datetime.utcnow()
    
    def to_dict(self, exclude_sensitive: bool = True) -> dict:
        """Convert model to dictionary for serialization"""
        exclude_fields = set()
        if exclude_sensitive:
            exclude_fields = {"token_hash"}
        return self.model_dump(mode="json", exclude=exclude_fields)
    
    def __str__(self) -> str:
        return f"Token({self.token_id})"
    
    def __repr__(self) -> str:
        return f"<Token id='{self.token_id}' user_id='{self.user_id}' valid={self.is_valid}>"