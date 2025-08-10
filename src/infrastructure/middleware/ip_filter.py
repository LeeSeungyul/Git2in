"""IP filtering middleware for FastAPI"""

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional

from src.infrastructure.security.ip_filter import ip_filter_service
from src.infrastructure.logging import get_logger
from src.infrastructure.middleware.correlation import get_correlation_id

logger = get_logger(__name__)


class IPFilterMiddleware(BaseHTTPMiddleware):
    """Middleware for IP-based access filtering"""
    
    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
    
    async def dispatch(self, request: Request, call_next):
        """Process request with IP filtering"""
        
        if not self.enabled:
            return await call_next(request)
        
        # Skip filtering for health check and metrics
        if request.url.path in ["/health", "/metrics", "/"]:
            return await call_next(request)
        
        # Extract client IP
        client_ip = self._get_client_ip(request)
        
        # Extract resource from path
        resource_id = self._extract_resource_id(request.url.path)
        
        # Check IP filter
        allowed, reason = ip_filter_service.check_ip(
            ip=client_ip,
            resource_id=resource_id,
            user_id=None,  # Not available at middleware level
            bypass_token=request.headers.get("X-IP-Bypass-Token")
        )
        
        if not allowed:
            logger.warning(
                "ip_filter_middleware_blocked",
                ip=client_ip,
                path=request.url.path,
                reason=reason,
                correlation_id=get_correlation_id()
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {reason}"
            )
        
        # Add client IP to request state for downstream use
        request.state.client_ip = client_ip
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header (from proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (original client)
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _extract_resource_id(self, path: str) -> Optional[str]:
        """Extract resource identifier from path"""
        # Remove leading/trailing slashes
        path = path.strip("/")
        parts = path.split("/")
        
        if not parts:
            return None
        
        # Git endpoints: /git/{namespace}/{repo}/...
        if parts[0] == "git" and len(parts) >= 3:
            namespace = parts[1]
            repo = parts[2].replace(".git", "")
            return f"repo:{namespace}/{repo}"
        
        # Namespace endpoints: /namespaces/{namespace}/...
        if parts[0] == "namespaces" and len(parts) >= 2:
            return f"namespace:{parts[1]}"
        
        # API versioned endpoints
        if parts[0] == "api" and len(parts) >= 2:
            # Skip version
            api_parts = parts[2:] if len(parts) > 2 else []
            if api_parts:
                return f"api:{'/'.join(api_parts)}"
        
        return None