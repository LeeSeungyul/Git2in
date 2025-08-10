"""Metrics collection middleware for FastAPI"""

import time
from typing import Callable, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.infrastructure.metrics import (
    http_request_duration_seconds,
    http_requests_total,
    http_response_size_bytes,
    http_request_size_bytes,
    http_requests_in_progress
)
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting HTTP metrics"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.exclude_paths = {
            "/metrics",  # Don't track metrics endpoint itself
            "/health",   # Health checks are too frequent
            "/ready"     # Readiness checks are too frequent
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics"""
        
        # Skip metrics for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Extract endpoint pattern (normalize path parameters)
        endpoint = self._normalize_endpoint(request.url.path)
        method = request.method
        
        # Track request size
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                http_request_size_bytes.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(size)
            except ValueError:
                pass
        
        # Track in-progress requests
        http_requests_in_progress.labels(
            method=method,
            endpoint=endpoint
        ).inc()
        
        # Track request duration
        start_time = time.time()
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Get response size from headers
            response_size = 0
            if hasattr(response, "headers"):
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        response_size = int(content_length)
                    except ValueError:
                        pass
            
            # Record metrics
            status = str(response.status_code)
            
            http_request_duration_seconds.labels(
                method=method,
                endpoint=endpoint,
                status=status
            ).observe(duration)
            
            http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status=status
            ).inc()
            
            if response_size > 0:
                http_response_size_bytes.labels(
                    method=method,
                    endpoint=endpoint,
                    status=status
                ).observe(response_size)
            
            # Log slow requests
            if duration > 1.0:
                logger.warning(
                    "slow_request",
                    method=method,
                    endpoint=endpoint,
                    duration_seconds=duration,
                    status=status
                )
            
            return response
            
        except Exception as e:
            # Track failed requests
            duration = time.time() - start_time
            
            http_request_duration_seconds.labels(
                method=method,
                endpoint=endpoint,
                status="500"
            ).observe(duration)
            
            http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status="500"
            ).inc()
            
            logger.error(
                "request_failed",
                method=method,
                endpoint=endpoint,
                duration_seconds=duration,
                error=str(e)
            )
            
            raise
            
        finally:
            # Decrement in-progress counter
            http_requests_in_progress.labels(
                method=method,
                endpoint=endpoint
            ).dec()
    
    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for metrics labels"""
        
        # Remove trailing slash
        if path.endswith("/") and len(path) > 1:
            path = path[:-1]
        
        # Common patterns to normalize
        patterns = [
            # Git endpoints
            (r"/git/[^/]+/[^/]+/info/refs", "/git/{namespace}/{repo}/info/refs"),
            (r"/git/[^/]+/[^/]+/git-upload-pack", "/git/{namespace}/{repo}/git-upload-pack"),
            (r"/git/[^/]+/[^/]+/git-receive-pack", "/git/{namespace}/{repo}/git-receive-pack"),
            
            # API endpoints
            (r"/api/v\d+/namespaces/[^/]+", "/api/{version}/namespaces/{namespace}"),
            (r"/api/v\d+/namespaces/[^/]+/repos", "/api/{version}/namespaces/{namespace}/repos"),
            (r"/api/v\d+/namespaces/[^/]+/repos/[^/]+", "/api/{version}/namespaces/{namespace}/repos/{repo}"),
            
            # Auth endpoints
            (r"/auth/token/[^/]+", "/auth/token/{token_id}"),
            (r"/auth/revoke/[^/]+", "/auth/revoke/{token_id}"),
            
            # User endpoints
            (r"/users/[^/]+", "/users/{user_id}"),
            (r"/users/[^/]+/tokens", "/users/{user_id}/tokens"),
        ]
        
        import re
        for pattern, replacement in patterns:
            if re.match(pattern, path):
                return replacement
        
        # If no pattern matches, use the path as-is (but limit length)
        if len(path) > 50:
            # Truncate very long paths to avoid cardinality explosion
            return path[:50] + "..."
        
        return path