import json
import time
from typing import Any, Callable, Dict, Optional

from fastapi import Request, Response
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import settings
from src.infrastructure.logging import (bind_context, clear_context,
                                        get_logger, unbind_context)
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Enhanced request/response logging middleware"""

    def __init__(self, app):
        super().__init__(app)
        self.exclude_paths = {
            "/health",  # Don't log health checks
            "/ready",  # Don't log readiness checks
            "/metrics",  # Don't log metrics endpoint
        }
        self.sample_body_paths = {
            "/auth/token",  # Sample auth requests
            "/git",  # Sample git operations
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()

        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Extract request metadata
        request_id = get_correlation_id()
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")

        # Extract authentication info if present
        user_id = None
        username = None
        if hasattr(request.state, "user"):
            user_id = getattr(request.state.user, "id", None)
            username = getattr(request.state.user, "username", None)

        # Bind context for all logs in this request
        bind_context(
            correlation_id=request_id,
            request_method=request.method,
            request_path=request.url.path,
            client_ip=client_ip,
            user_agent=user_agent,
            user_id=user_id,
            username=username,
        )

        # Extract namespace and repository from path if present
        namespace, repository = self._extract_git_context(request.url.path)
        if namespace:
            bind_context(namespace=namespace)
        if repository:
            bind_context(repository=repository)

        # Log request details
        request_size = request.headers.get("content-length", 0)

        # Sample request body if configured and in development
        request_body_sample = None
        if settings.is_development and self._should_sample_body(request.url.path):
            request_body_sample = await self._sample_request_body(request)

        logger.info(
            "http_request_started",
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params) if request.query_params else None,
            headers=self._sanitize_headers(request.headers),
            request_size=request_size,
            body_sample=request_body_sample,
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate metrics
            duration = time.time() - start_time
            response_size = response.headers.get("content-length", 0)

            # Log successful response
            logger.info(
                "http_request_completed",
                status_code=response.status_code,
                duration_ms=round(duration * 1000, 2),
                response_size=response_size,
                response_headers=self._sanitize_headers(response.headers),
            )

            # Add custom headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{round(duration * 1000, 2)}ms"

            return response

        except Exception as e:
            duration = time.time() - start_time

            # Log error
            logger.error(
                "http_request_failed",
                duration_ms=round(duration * 1000, 2),
                error_type=type(e).__name__,
                error_message=str(e),
                exc_info=True,
            )
            raise

        finally:
            # Clear context
            clear_context()

    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP from request"""
        # Check X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        if request.client:
            return request.client.host

        return "unknown"

    def _extract_git_context(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """Extract namespace and repository from Git paths"""
        import re

        # Match Git HTTP paths
        git_pattern = r"^/git/([^/]+)/([^/]+)"
        match = re.match(git_pattern, path)
        if match:
            namespace = match.group(1)
            repo = match.group(2).replace(".git", "")
            return namespace, repo

        # Match API paths
        api_pattern = r"^/api/v\d+/namespaces/([^/]+)/repos/([^/]+)"
        match = re.match(api_pattern, path)
        if match:
            namespace = match.group(1)
            repo = match.group(2)
            return namespace, repo

        return None, None

    def _sanitize_headers(self, headers: Headers) -> Dict[str, str]:
        """Sanitize headers for logging"""
        sensitive_headers = {
            "authorization",
            "x-api-key",
            "x-auth-token",
            "cookie",
            "set-cookie",
        }

        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def _should_sample_body(self, path: str) -> bool:
        """Check if request body should be sampled"""
        for sample_path in self.sample_body_paths:
            if path.startswith(sample_path):
                return True
        return False

    async def _sample_request_body(
        self, request: Request, max_size: int = 1000
    ) -> Optional[str]:
        """Sample request body for debugging"""
        try:
            # Get content type
            content_type = request.headers.get("content-type", "")

            # Only sample JSON and form data
            if (
                "application/json" in content_type
                or "application/x-www-form-urlencoded" in content_type
            ):
                # Read body (this consumes the stream, so we need to restore it)
                body = await request.body()

                # Restore body for downstream handlers
                async def receive():
                    return {"type": "http.request", "body": body}

                request._receive = receive

                # Sample body
                if len(body) > max_size:
                    return body[:max_size].decode("utf-8", errors="ignore") + "..."
                else:
                    return body.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.debug("Failed to sample request body", error=str(e))

        return None
