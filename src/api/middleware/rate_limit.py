"""Rate limiting middleware to prevent API abuse."""

import time
from typing import Dict, Tuple, Callable, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from src.api.models.common_models import ErrorResponse

logger = structlog.get_logger()


class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""
    
    def __init__(self):
        # Store request timestamps for each key
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
        # Store cleanup timestamps
        self.last_cleanup: Dict[str, float] = {}
    
    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int, int]:
        """
        Check if request is allowed.
        
        Returns:
            Tuple of (allowed, remaining_requests, reset_timestamp)
        """
        now = time.time()
        cutoff = now - window_seconds
        
        # Clean up old requests every minute
        if key not in self.last_cleanup or now - self.last_cleanup[key] > 60:
            self._cleanup_old_requests(key, cutoff)
            self.last_cleanup[key] = now
        
        # Count requests in window
        request_times = self.requests[key]
        valid_requests = [t for t in request_times if t > cutoff]
        
        # Update the deque with only valid requests
        self.requests[key] = deque(valid_requests)
        
        # Check if limit exceeded
        if len(valid_requests) >= max_requests:
            # Find when the oldest request will expire
            oldest_request = min(valid_requests)
            reset_timestamp = int(oldest_request + window_seconds)
            return False, 0, reset_timestamp
        
        # Add current request
        self.requests[key].append(now)
        remaining = max_requests - len(self.requests[key])
        reset_timestamp = int(now + window_seconds)
        
        return True, remaining, reset_timestamp
    
    def _cleanup_old_requests(self, key: str, cutoff: float):
        """Remove requests older than cutoff."""
        self.requests[key] = deque(
            t for t in self.requests[key] if t > cutoff
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply rate limiting to API endpoints."""
    
    def __init__(self, app, settings):
        super().__init__(app)
        self.settings = settings
        self.limiter = RateLimiter()
        
        # Define rate limits for different endpoint groups
        self.rate_limits = {
            # Auth endpoints: stricter limits
            "auth": {"requests": 5, "window": 60},  # 5 per minute
            # User registration: prevent spam
            "register": {"requests": 3, "window": 3600},  # 3 per hour
            # Git operations: per repository
            "git": {"requests": 100, "window": 3600},  # 100 per hour
            # General API: authenticated users
            "authenticated": {"requests": 5000, "window": 3600},  # 5000 per hour
            # General API: unauthenticated
            "unauthenticated": {"requests": 60, "window": 3600},  # 60 per hour
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting based on endpoint and authentication status."""
        # Skip rate limiting for health checks
        if request.url.path in ["/api/v1/health", "/api/v1/ready", "/api/v1/alive"]:
            return await call_next(request)
        
        # Determine rate limit key and limits
        key, limit_config = self._get_rate_limit_key(request)
        
        if key and limit_config:
            # Check rate limit
            allowed, remaining, reset = self.limiter.is_allowed(
                key,
                limit_config["requests"],
                limit_config["window"]
            )
            
            if not allowed:
                # Rate limit exceeded
                retry_after = reset - int(time.time())
                request_id = getattr(request.state, 'request_id', None)
                
                response = JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content=ErrorResponse(
                        error="RATE_LIMITED",
                        message="API rate limit exceeded",
                        details={"retry_after": retry_after},
                        request_id=request_id
                    ).model_dump(),
                    headers={
                        "X-RateLimit-Limit": str(limit_config["requests"]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset),
                        "Retry-After": str(retry_after)
                    }
                )
                return response
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(limit_config["requests"])
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(reset)
            
            return response
        
        # No rate limiting applied
        return await call_next(request)
    
    def _get_rate_limit_key(self, request: Request) -> Tuple[Optional[str], Optional[Dict]]:
        """Determine rate limit key and configuration for the request."""
        path = request.url.path
        method = request.method
        
        # Auth endpoints
        if path == "/api/v1/auth/login":
            # Rate limit by IP for login attempts
            client_ip = request.client.host if request.client else "unknown"
            return f"auth:login:{client_ip}", self.rate_limits["auth"]
        
        # User registration
        if path == "/api/v1/users" and method == "POST":
            client_ip = request.client.host if request.client else "unknown"
            return f"register:{client_ip}", self.rate_limits["register"]
        
        # Git operations
        if ".git/" in path:
            # Extract repository path
            parts = path.split(".git/")[0].split("/")
            if len(parts) >= 2:
                owner, repo = parts[-2], parts[-1]
                # Rate limit per repository
                return f"git:{owner}/{repo}", self.rate_limits["git"]
        
        # Authenticated requests
        auth_header = request.headers.get("Authorization")
        if auth_header and hasattr(request.state, "current_user"):
            # Rate limit by user ID
            user_id = getattr(request.state.current_user, "id", "unknown")
            return f"user:{user_id}", self.rate_limits["authenticated"]
        
        # Unauthenticated requests
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}", self.rate_limits["unauthenticated"]