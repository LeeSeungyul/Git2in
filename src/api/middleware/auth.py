"""Authentication middleware for request validation."""

from typing import Optional, Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from src.api.models.common_models import ErrorResponse

logger = structlog.get_logger()


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Optional authentication middleware for protected routes."""
    
    def __init__(self, app, settings):
        super().__init__(app)
        self.settings = settings
        # Define public paths that don't require authentication
        self.public_paths = {
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/health",
            "/api/v1/ready", 
            "/api/v1/alive",
            "/api/v1/auth/login",
            "/api/v1/users",  # POST only (registration)
        }
        # Paths that support optional authentication
        self.optional_auth_paths = {
            "/api/v1/repositories",  # GET (list public repos)
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and validate authentication if needed."""
        path = request.url.path
        method = request.method
        
        # Check if path is public
        if self._is_public_path(path, method):
            return await call_next(request)
        
        # Check if path supports optional authentication
        if self._is_optional_auth_path(path, method):
            # Extract token if present but don't require it
            auth_header = request.headers.get("Authorization")
            if auth_header:
                request.state.auth_header = auth_header
            return await call_next(request)
        
        # Git HTTP endpoints have their own auth handling
        if self._is_git_http_path(path):
            return await call_next(request)
        
        # All other paths require authentication
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            request_id = getattr(request.state, 'request_id', None)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=ErrorResponse(
                    error="AUTHENTICATION_ERROR",
                    message="Authentication required",
                    request_id=request_id
                ).model_dump(),
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Store auth header for use in dependencies
        request.state.auth_header = auth_header
        
        return await call_next(request)
    
    def _is_public_path(self, path: str, method: str) -> bool:
        """Check if the path is public."""
        # Exact match
        if path in self.public_paths:
            # Special case for user registration
            if path == "/api/v1/users" and method != "POST":
                return False
            return True
        
        # Prefix match for static files
        if path.startswith("/static/"):
            return True
        
        return False
    
    def _is_optional_auth_path(self, path: str, method: str) -> bool:
        """Check if the path supports optional authentication."""
        # Repository endpoints
        if path == "/api/v1/repositories" and method == "GET":
            return True
        
        # Individual repository GET (public repos)
        if path.startswith("/api/v1/repositories/") and method == "GET":
            return True
        
        return False
    
    def _is_git_http_path(self, path: str) -> bool:
        """Check if the path is a Git HTTP endpoint."""
        # Git paths end with .git/... or contain .git/
        return ".git/" in path or path.endswith(".git")