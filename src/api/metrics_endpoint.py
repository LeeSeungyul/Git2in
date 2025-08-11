"""Prometheus metrics endpoint with access control"""

from typing import Optional

from fastapi import (APIRouter, Depends, HTTPException, Request, Response,
                     status)
from fastapi.responses import PlainTextResponse

from src.api.auth.dependencies import OptionalToken
from src.core.auth.models import TokenScope
from src.core.config import settings
from src.infrastructure.logging import get_logger
from src.infrastructure.metrics import get_metrics, get_metrics_content_type
from src.infrastructure.security.ip_filter import ip_filter_service

logger = get_logger(__name__)

router = APIRouter(tags=["metrics"])


class MetricsAccessControl:
    """Access control for metrics endpoint"""

    def __init__(self):
        # Allowed IPs for metrics access (in addition to token auth)
        self.allowed_ips = (
            settings.metrics_allowed_ips
            if hasattr(settings, "metrics_allowed_ips")
            else ["127.0.0.1", "::1"]  # IPv6 localhost
        )

        # Required token scope for metrics access
        self.required_scope = TokenScope.ADMIN

    def check_access(
        self, request: Request, token: Optional[OptionalToken] = None
    ) -> bool:
        """Check if request has access to metrics"""

        # Check if metrics endpoint is enabled
        if (
            not settings.metrics_enabled
            if hasattr(settings, "metrics_enabled")
            else True
        ):
            return False

        # Check token-based access
        if token and hasattr(token, "has_scope"):
            if token.has_scope(self.required_scope):
                logger.debug("metrics_access_granted_by_token", user_id=token.sub)
                return True

        # Check IP-based access
        client_ip = self._get_client_ip(request)

        # Check against allowed IPs
        for allowed_ip in self.allowed_ips:
            if self._ip_matches(client_ip, allowed_ip):
                logger.debug("metrics_access_granted_by_ip", client_ip=client_ip)
                return True

        # In production, check with IP filter service if configured
        # In development, still require explicit authentication
        if settings.is_production:
            try:
                allowed, reason = ip_filter_service.check_ip(
                    client_ip,
                    resource_id="metrics",
                    bypass_token=request.headers.get("X-Metrics-Token"),
                )
                if allowed:
                    logger.debug(
                        "metrics_access_granted_by_filter",
                        client_ip=client_ip,
                        reason=reason,
                    )
                    return True
            except Exception as e:
                logger.error("metrics_ip_filter_check_failed", error=str(e))

        logger.warning(
            "metrics_access_denied", client_ip=client_ip, has_token=token is not None
        )
        return False

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
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

        return ""

    def _ip_matches(self, client_ip: str, allowed_ip: str) -> bool:
        """Check if client IP matches allowed IP (supports CIDR)"""
        import ipaddress

        try:
            # Parse client IP
            client = ipaddress.ip_address(client_ip)

            # Check if allowed_ip is a network or single IP
            if "/" in allowed_ip:
                # CIDR notation
                network = ipaddress.ip_network(allowed_ip, strict=False)
                return client in network
            else:
                # Single IP
                return client == ipaddress.ip_address(allowed_ip)
        except (ValueError, ipaddress.AddressValueError):
            # Fall back to string comparison
            return client_ip == allowed_ip


# Global access control instance
metrics_access = MetricsAccessControl()


async def require_metrics_access(request: Request, token: OptionalToken = None):
    """Dependency to require metrics access"""
    if not metrics_access.check_access(request, token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to metrics endpoint is forbidden",
        )


@router.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics(
    request: Request,
    _: None = Depends(require_metrics_access),
    token: OptionalToken = None,
):
    """
    Prometheus metrics endpoint

    Returns metrics in Prometheus text format.
    Access is controlled by token scope or IP allowlist.
    """
    try:
        # Generate metrics
        metrics_data = get_metrics()

        # Log metrics access
        logger.info(
            "metrics_accessed",
            user_id=token.sub if token else None,
            client_ip=metrics_access._get_client_ip(request),
        )

        # Return metrics with proper content type
        return Response(
            content=metrics_data,
            media_type=get_metrics_content_type(),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    except Exception as e:
        logger.error("metrics_generation_failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate metrics",
        )


@router.get("/metrics/json")
async def get_metrics_json(
    request: Request,
    _: None = Depends(require_metrics_access),
    token: OptionalToken = None,
):
    """
    Get metrics in JSON format (for debugging)

    This endpoint is useful for debugging metric values.
    Returns a simplified JSON representation of current metrics.
    """
    try:
        import json

        from prometheus_client import REGISTRY

        metrics_dict = {}

        # Collect all metrics from registry
        for collector in REGISTRY._collector_to_names:
            for metric in collector.collect():
                metric_dict = {
                    "name": metric.name,
                    "documentation": metric.documentation,
                    "type": metric.type,
                    "samples": [],
                }

                for sample in metric.samples:
                    sample_dict = {"labels": sample.labels, "value": sample.value}
                    metric_dict["samples"].append(sample_dict)

                metrics_dict[metric.name] = metric_dict

        logger.info(
            "metrics_json_accessed",
            user_id=token.sub if token else None,
            client_ip=metrics_access._get_client_ip(request),
        )

        return metrics_dict

    except Exception as e:
        logger.error("metrics_json_generation_failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate metrics JSON",
        )
