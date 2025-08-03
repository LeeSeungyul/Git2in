"""Request/response logging middleware."""

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

logger = structlog.get_logger()


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests and responses with timing information."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log details."""
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Bind request context to logger
        with structlog.contextvars.bound_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None
        ):
            # Log request
            logger.info(
                "Request started",
                query_params=dict(request.query_params) if request.query_params else None,
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ["authorization", "cookie", "x-api-key"]
                }
            )
            
            # Time the request
            start_time = time.time()
            
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            # Log response
            logger.info(
                "Request completed",
                status_code=response.status_code,
                duration_ms=duration_ms
            )
            
            return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Ensure request ID is present for all requests."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID if not present."""
        # Check if request ID already exists
        if not hasattr(request.state, 'request_id'):
            request.state.request_id = str(uuid.uuid4())
        
        response = await call_next(request)
        
        # Ensure request ID is in response headers
        if "X-Request-ID" not in response.headers:
            response.headers["X-Request-ID"] = request.state.request_id
        
        return response