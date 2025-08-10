"""Authentication and token models"""

from typing import Optional, List, Dict, Any, Set
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator, ConfigDict
import time

from src.core.exceptions import ValidationError


class TokenScope(str, Enum):
    """Token permission scopes"""
    # Global scopes
    ADMIN = "admin"  # Full administrative access
    
    # Namespace scopes
    NAMESPACE_READ = "namespace:read"
    NAMESPACE_WRITE = "namespace:write"
    NAMESPACE_ADMIN = "namespace:admin"
    
    # Repository scopes
    REPO_READ = "repo:read"
    REPO_WRITE = "repo:write"
    REPO_ADMIN = "repo:admin"
    
    # User management scopes
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    
    # Token management scopes
    TOKEN_CREATE = "token:create"
    TOKEN_REVOKE = "token:revoke"
    
    @classmethod
    def parse_scope(cls, scope_str: str) -> "TokenScope":
        """Parse a scope string, handling wildcards"""
        try:
            return cls(scope_str)
        except ValueError:
            raise ValidationError(f"Invalid scope: {scope_str}")
    
    def implies(self, other: "TokenScope") -> bool:
        """Check if this scope implies another scope"""
        # Admin implies everything
        if self == TokenScope.ADMIN:
            return True
        
        # Write implies read for same resource
        if self == TokenScope.NAMESPACE_WRITE and other == TokenScope.NAMESPACE_READ:
            return True
        if self == TokenScope.REPO_WRITE and other == TokenScope.REPO_READ:
            return True
        if self == TokenScope.USER_WRITE and other == TokenScope.USER_READ:
            return True
        
        # Admin scopes imply read/write for same resource
        if self == TokenScope.NAMESPACE_ADMIN:
            return other in [TokenScope.NAMESPACE_READ, TokenScope.NAMESPACE_WRITE]
        if self == TokenScope.REPO_ADMIN:
            return other in [TokenScope.REPO_READ, TokenScope.REPO_WRITE]
        
        # Exact match
        return self == other


class TokenType(str, Enum):
    """Types of tokens"""
    ACCESS = "access"  # Regular access token
    REFRESH = "refresh"  # Refresh token for getting new access tokens
    API_KEY = "api_key"  # Long-lived API key
    TEMPORARY = "temporary"  # Short-lived temporary token


class TokenClaims(BaseModel):
    """JWT-like token claims structure"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    # Standard claims
    sub: str = Field(..., description="Subject (user ID or identifier)")
    iat: int = Field(default_factory=lambda: int(time.time()), description="Issued at timestamp")
    exp: int = Field(..., description="Expiration timestamp")
    jti: str = Field(default_factory=lambda: str(uuid4()), description="JWT ID for uniqueness")
    
    # Custom claims
    token_type: TokenType = Field(default=TokenType.ACCESS, description="Type of token")
    scopes: List[TokenScope] = Field(default_factory=list, description="Permission scopes")
    namespace: Optional[str] = Field(None, description="Target namespace (if scoped)")
    repository: Optional[str] = Field(None, description="Target repository (if scoped)")
    
    # Metadata
    user_id: Optional[UUID] = Field(None, description="Internal user ID")
    username: Optional[str] = Field(None, description="Username for display")
    email: Optional[str] = Field(None, description="User email")
    
    # Security metadata
    ip_address: Optional[str] = Field(None, description="IP address token was issued to")
    user_agent: Optional[str] = Field(None, description="User agent of token requester")
    
    # Additional custom claims
    extra: Dict[str, Any] = Field(default_factory=dict, description="Additional custom claims")
    
    @field_validator("exp")
    @classmethod
    def validate_expiration(cls, v: int, info) -> int:
        """Validate expiration is in the future"""
        if "iat" in info.data and v <= info.data["iat"]:
            raise ValidationError("Token expiration must be after issued time")
        return v
    
    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: List[TokenScope]) -> List[TokenScope]:
        """Validate and deduplicate scopes"""
        # Remove duplicates while preserving order
        seen = set()
        unique_scopes = []
        for scope in v:
            if scope not in seen:
                seen.add(scope)
                unique_scopes.append(scope)
        return unique_scopes
    
    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, v: Optional[str], info) -> Optional[str]:
        """Validate namespace if namespace-scoped permissions exist"""
        if v and info.data.get("scopes"):
            scopes = info.data["scopes"]
            namespace_scopes = [s for s in scopes if "namespace:" in s.value]
            if namespace_scopes and not v:
                raise ValidationError("Namespace required for namespace-scoped permissions")
        return v
    
    @field_validator("repository")
    @classmethod
    def validate_repository(cls, v: Optional[str], info) -> Optional[str]:
        """Validate repository if repo-scoped permissions exist"""
        if v and info.data.get("scopes"):
            scopes = info.data["scopes"]
            repo_scopes = [s for s in scopes if "repo:" in s.value]
            if repo_scopes and not v:
                raise ValidationError("Repository required for repository-scoped permissions")
        return v
    
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return int(time.time()) >= self.exp
    
    def has_scope(self, required_scope: TokenScope) -> bool:
        """Check if token has a specific scope (including implied scopes)"""
        for scope in self.scopes:
            if scope.implies(required_scope):
                return True
        return False
    
    def has_any_scope(self, required_scopes: List[TokenScope]) -> bool:
        """Check if token has any of the required scopes"""
        return any(self.has_scope(scope) for scope in required_scopes)
    
    def has_all_scopes(self, required_scopes: List[TokenScope]) -> bool:
        """Check if token has all required scopes"""
        return all(self.has_scope(scope) for scope in required_scopes)
    
    def remaining_lifetime(self) -> timedelta:
        """Get remaining lifetime of token"""
        remaining_seconds = self.exp - int(time.time())
        return timedelta(seconds=max(0, remaining_seconds))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert claims to dictionary for serialization"""
        data = {
            "sub": self.sub,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "token_type": self.token_type.value,
            "scopes": [scope.value for scope in self.scopes],
        }
        
        # Add optional fields if present
        if self.namespace:
            data["namespace"] = self.namespace
        if self.repository:
            data["repository"] = self.repository
        if self.user_id:
            data["user_id"] = str(self.user_id)
        if self.username:
            data["username"] = self.username
        if self.email:
            data["email"] = self.email
        if self.ip_address:
            data["ip_address"] = self.ip_address
        if self.user_agent:
            data["user_agent"] = self.user_agent
        
        # Add extra claims
        data.update(self.extra)
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenClaims":
        """Create claims from dictionary"""
        # Convert scope strings back to TokenScope enums
        if "scopes" in data:
            data["scopes"] = [TokenScope(s) for s in data["scopes"]]
        
        # Convert token_type string to enum
        if "token_type" in data:
            data["token_type"] = TokenType(data["token_type"])
        
        # Convert user_id string to UUID
        if "user_id" in data and isinstance(data["user_id"], str):
            data["user_id"] = UUID(data["user_id"])
        
        # Extract known fields
        known_fields = {
            "sub", "iat", "exp", "jti", "token_type", "scopes",
            "namespace", "repository", "user_id", "username", "email",
            "ip_address", "user_agent"
        }
        
        # Separate extra claims
        extra = {k: v for k, v in data.items() if k not in known_fields}
        
        # Create claims object
        claims_data = {k: v for k, v in data.items() if k in known_fields}
        claims_data["extra"] = extra
        
        return cls(**claims_data)


class TokenHeader(BaseModel):
    """Token header for algorithm and key information"""
    alg: str = Field(default="HS256", description="Signing algorithm")
    typ: str = Field(default="JWT", description="Token type")
    kid: Optional[str] = Field(None, description="Key ID for key rotation")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert header to dictionary"""
        data = {"alg": self.alg, "typ": self.typ}
        if self.kid:
            data["kid"] = self.kid
        return data


class Token(BaseModel):
    """Complete token structure"""
    header: TokenHeader
    claims: TokenClaims
    signature: Optional[str] = None
    
    @property
    def token_id(self) -> str:
        """Get token ID (jti)"""
        return self.claims.jti
    
    @property
    def user_id(self) -> Optional[UUID]:
        """Get user ID from claims"""
        return self.claims.user_id
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return self.claims.is_expired()
    
    def encode_payload(self) -> str:
        """Encode header and claims for signing"""
        import json
        import base64
        
        # Encode header
        header_json = json.dumps(self.header.to_dict(), separators=(",", ":"))
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()
        
        # Encode claims
        claims_json = json.dumps(self.claims.to_dict(), separators=(",", ":"))
        claims_b64 = base64.urlsafe_b64encode(claims_json.encode()).rstrip(b"=").decode()
        
        return f"{header_b64}.{claims_b64}"


class TokenRevocation(BaseModel):
    """Token revocation record"""
    jti: str = Field(..., description="JWT ID of revoked token")
    revoked_at: datetime = Field(default_factory=datetime.utcnow)
    reason: Optional[str] = Field(None, description="Revocation reason")
    revoked_by: Optional[str] = Field(None, description="User who revoked the token")
    expires_at: datetime = Field(..., description="When the revocation record can be deleted")
    
    def is_expired(self) -> bool:
        """Check if revocation record can be deleted"""
        return datetime.utcnow() >= self.expires_at


class TokenRequest(BaseModel):
    """Request for creating a new token"""
    user_id: UUID
    username: str
    email: Optional[str] = None
    scopes: List[TokenScope] = Field(default_factory=list)
    token_type: TokenType = TokenType.ACCESS
    ttl_seconds: Optional[int] = Field(None, description="Token lifetime in seconds")
    namespace: Optional[str] = None
    repository: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    extra_claims: Dict[str, Any] = Field(default_factory=dict)
    
    @field_validator("ttl_seconds")
    @classmethod
    def validate_ttl(cls, v: Optional[int]) -> Optional[int]:
        """Validate TTL is positive"""
        if v is not None and v <= 0:
            raise ValidationError("TTL must be positive")
        # Max TTL of 1 year
        if v is not None and v > 31536000:
            raise ValidationError("TTL cannot exceed 1 year")
        return v


class TokenValidationResult(BaseModel):
    """Result of token validation"""
    valid: bool
    claims: Optional[TokenClaims] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    
    @classmethod
    def success(cls, claims: TokenClaims) -> "TokenValidationResult":
        """Create successful validation result"""
        return cls(valid=True, claims=claims)
    
    @classmethod
    def failure(cls, error: str, error_code: str = "INVALID_TOKEN") -> "TokenValidationResult":
        """Create failed validation result"""
        return cls(valid=False, error=error, error_code=error_code)