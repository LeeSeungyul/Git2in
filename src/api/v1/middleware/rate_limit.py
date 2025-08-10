"""Rate limiting middleware using slowapi"""

from typing import Optional, Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import time

from src.api.v1.models.errors import ErrorResponse
from src.core.config import settings
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)


def get_request_identifier(request: Request) -> str:
    """Get identifier for rate limiting (IP or user ID)"""
    # Try to get user ID from token
    if hasattr(request.state, "token_claims") and request.state.token_claims:
        return f"user:{request.state.token_claims.sub}"
    
    # Fall back to IP address
    return get_remote_address(request)


def create_limiter() -> Limiter:
    """Create and configure the rate limiter"""
    limiter = Limiter(
        key_func=get_request_identifier,
        default_limits=["1000 per hour", "100 per minute"],  # Global defaults
        storage_uri=None,  # In-memory storage (use Redis in production)
        strategy="fixed-window",
        headers_enabled=True,
        swallow_errors=False
    )
    return limiter


# Global limiter instance
limiter = create_limiter()


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Custom handler for rate limit exceeded errors"""
    correlation_id = get_correlation_id()
    
    # Parse retry-after from exception message
    retry_after = 60  # Default to 60 seconds
    if hasattr(exc, 'retry_after'):
        retry_after = exc.retry_after
    
    logger.warning(
        "rate_limit_exceeded",
        path=str(request.url.path),
        method=request.method,
        identifier=get_request_identifier(request),
        retry_after=retry_after,
        correlation_id=correlation_id
    )
    
    error_response = ErrorResponse.rate_limit_exceeded(
        retry_after=retry_after,
        correlation_id=correlation_id,
        path=str(request.url.path),
        method=request.method
    )
    
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=error_response.model_dump(),
        headers={
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(exc.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(time.time()) + retry_after)
        }
    )


class RateLimitConfig:
    """Configuration for rate limiting"""
    
    # Endpoint-specific limits
    ENDPOINT_LIMITS = {
        # Authentication endpoints
        "/api/v1/auth/token": "5 per minute",  # Login attempts
        "/api/v1/users": "10 per hour",  # User registration
        
        # Write operations
        "POST:/api/v1/namespaces": "20 per hour",
        "POST:/api/v1/namespaces/*/repos": "30 per hour",
        "DELETE:/api/v1/namespaces/*": "10 per hour",
        "DELETE:/api/v1/namespaces/*/repos/*": "20 per hour",
        
        # API token operations
        "/api/v1/tokens": "10 per hour",  # Token creation
        "/api/v1/tokens/*/rotate": "5 per hour",  # Token rotation
        
        # Git operations (higher limits)
        "/git/*/info/refs": "1000 per minute",
        "/git/*/git-upload-pack": "500 per minute",
        "/git/*/git-receive-pack": "100 per minute",
    }
    
    # User role-based limits
    ROLE_LIMITS = {
        "admin": ["10000 per hour", "1000 per minute"],
        "authenticated": ["5000 per hour", "500 per minute"],
        "anonymous": ["1000 per hour", "100 per minute"]
    }
    
    # Bypass for internal services
    BYPASS_IPS = [
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]


def get_user_role(request: Request) -> str:
    """Get user role for rate limiting"""
    if hasattr(request.state, "token_claims") and request.state.token_claims:
        if request.state.token_claims.is_admin:
            return "admin"
        return "authenticated"
    return "anonymous"


def should_bypass_rate_limit(request: Request) -> bool:
    """Check if request should bypass rate limiting"""
    # Check if in development mode
    if settings.is_development:
        return False  # Still apply rate limits in development for testing
    
    # Check bypass IPs
    client_ip = get_remote_address(request)
    if client_ip in RateLimitConfig.BYPASS_IPS:
        return True
    
    # Check for admin bypass token
    if request.headers.get("X-Admin-Bypass-Token") == settings.signing_key:
        logger.info(
            "rate_limit_bypassed",
            reason="admin_token",
            path=str(request.url.path)
        )
        return True
    
    return False


def get_endpoint_limit(request: Request) -> Optional[str]:
    """Get specific rate limit for an endpoint"""
    path = str(request.url.path)
    method = request.method
    
    # Check exact path match
    if path in RateLimitConfig.ENDPOINT_LIMITS:
        return RateLimitConfig.ENDPOINT_LIMITS[path]
    
    # Check method:path pattern
    method_path = f"{method}:{path}"
    if method_path in RateLimitConfig.ENDPOINT_LIMITS:
        return RateLimitConfig.ENDPOINT_LIMITS[method_path]
    
    # Check wildcard patterns
    for pattern, limit in RateLimitConfig.ENDPOINT_LIMITS.items():
        if "*" in pattern:
            # Simple wildcard matching (in production, use proper pattern matching)
            pattern_parts = pattern.replace("*", ".*")
            import re
            if re.match(pattern_parts, path) or re.match(pattern_parts, method_path):
                return limit
    
    # Default to role-based limits
    role = get_user_role(request)
    return RateLimitConfig.ROLE_LIMITS.get(role, ["1000 per hour"])[0]


# Decorator for applying rate limits to specific endpoints
def rate_limit(limit: str):
    """Decorator to apply rate limiting to an endpoint"""
    def decorator(func: Callable) -> Callable:
        return limiter.limit(limit)(func)
    return decorator


# Common rate limit decorators
auth_rate_limit = rate_limit("5 per minute")
write_rate_limit = rate_limit("30 per minute")
read_rate_limit = rate_limit("100 per minute")
admin_rate_limit = rate_limit("1000 per minute")