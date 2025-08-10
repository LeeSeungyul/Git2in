"""Prometheus metrics collection and registry"""

from typing import Optional, Dict, Any, List
from prometheus_client import (
    Counter, Histogram, Gauge, Info, Summary,
    CollectorRegistry, REGISTRY,
    generate_latest, CONTENT_TYPE_LATEST
)
from prometheus_client.metrics import MetricWrapperBase
import time
from functools import wraps
import asyncio

from src.core.config import settings


# Create a custom registry for our metrics
metrics_registry = REGISTRY  # Use default registry for compatibility

# ====================
# Service Information
# ====================

service_info = Info(
    "git2in_service",
    "Git2in service information",
    registry=metrics_registry
)

# Set service info
service_info.info({
    "version": settings.app_version,
    "environment": settings.environment,
    "service": "git2in"
})

# ====================
# HTTP Metrics
# ====================

# HTTP request duration in seconds
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint", "status"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=metrics_registry
)

# Total HTTP requests
http_requests_total = Counter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status"],
    registry=metrics_registry
)

# HTTP response size in bytes
http_response_size_bytes = Histogram(
    "http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint", "status"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
    registry=metrics_registry
)

# HTTP request size in bytes
http_request_size_bytes = Histogram(
    "http_request_size_bytes",
    "HTTP request body size in bytes",
    ["method", "endpoint"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
    registry=metrics_registry
)

# Concurrent HTTP requests
http_requests_in_progress = Gauge(
    "http_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"],
    registry=metrics_registry
)

# ====================
# Git Operation Metrics
# ====================

# Git operations counter
git_operations_total = Counter(
    "git_operations_total",
    "Total number of Git operations",
    ["operation", "namespace", "repository", "status"],
    registry=metrics_registry
)

# Git pack file size
git_pack_objects_bytes = Histogram(
    "git_pack_objects_bytes",
    "Size of Git pack objects in bytes",
    ["operation", "namespace", "repository"],
    buckets=(1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000),
    registry=metrics_registry
)

# Git negotiation rounds
git_negotiation_rounds = Counter(
    "git_negotiation_rounds",
    "Number of pack negotiation rounds",
    ["operation", "namespace", "repository"],
    registry=metrics_registry
)

# Repository size gauge
repository_size_bytes = Gauge(
    "repository_size_bytes",
    "Repository size in bytes",
    ["namespace", "repository"],
    registry=metrics_registry
)

# Git operation duration
git_operation_duration_seconds = Histogram(
    "git_operation_duration_seconds",
    "Git operation duration in seconds",
    ["operation", "namespace", "repository"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
    registry=metrics_registry
)

# Ref advertisement time
git_ref_advertisement_duration_seconds = Histogram(
    "git_ref_advertisement_duration_seconds",
    "Time to advertise refs in seconds",
    ["namespace", "repository"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    registry=metrics_registry
)

# Object enumeration duration
git_object_enumeration_duration_seconds = Histogram(
    "git_object_enumeration_duration_seconds",
    "Time to enumerate objects in seconds",
    ["operation", "namespace", "repository"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=metrics_registry
)

# ====================
# Authentication Metrics
# ====================

# Authentication attempts
auth_attempts_total = Counter(
    "auth_attempts_total",
    "Total number of authentication attempts",
    ["method", "status"],
    registry=metrics_registry
)

# Token operations
token_operations_total = Counter(
    "token_operations_total",
    "Total number of token operations",
    ["operation", "status"],
    registry=metrics_registry
)

# Active tokens gauge
active_tokens = Gauge(
    "active_tokens",
    "Number of active tokens",
    ["token_type"],
    registry=metrics_registry
)

# ====================
# Authorization Metrics
# ====================

# Authorization checks
authorization_checks_total = Counter(
    "authorization_checks_total",
    "Total number of authorization checks",
    ["resource_type", "action", "result"],
    registry=metrics_registry
)

# Authorization cache metrics
authorization_cache_hits = Counter(
    "authorization_cache_hits",
    "Number of authorization cache hits",
    registry=metrics_registry
)

authorization_cache_misses = Counter(
    "authorization_cache_misses",
    "Number of authorization cache misses",
    registry=metrics_registry
)

# ====================
# System Metrics
# ====================

# Process start time (unix timestamp)
process_start_time = Gauge(
    "process_start_time_seconds",
    "Start time of the process since unix epoch in seconds",
    registry=metrics_registry
)

# Set process start time
process_start_time.set(time.time())

# Health check status
health_check_status = Gauge(
    "health_check_status",
    "Health check status (1 = healthy, 0 = unhealthy)",
    ["check_type"],
    registry=metrics_registry
)

# ====================
# Logging Metrics
# ====================

# Log messages counter
log_messages_total = Counter(
    "log_messages_total",
    "Total number of log messages",
    ["level", "logger"],
    registry=metrics_registry
)

# ====================
# IP Filter Metrics
# ====================

# IP filter decisions
ip_filter_decisions_total = Counter(
    "ip_filter_decisions_total",
    "Total number of IP filter decisions",
    ["action", "reason"],
    registry=metrics_registry
)

# Rate limit hits
rate_limit_hits_total = Counter(
    "rate_limit_hits_total",
    "Total number of rate limit hits",
    ["ip"],
    registry=metrics_registry
)

# ====================
# Audit Metrics
# ====================

# Audit events
audit_events_total = Counter(
    "audit_events_total",
    "Total number of audit events",
    ["action", "result"],
    registry=metrics_registry
)

# ====================
# Utility Functions
# ====================

def track_time(metric: Histogram, **labels):
    """Decorator to track execution time of a function"""
    def decorator(func):
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                metric.labels(**labels).observe(duration)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                metric.labels(**labels).observe(duration)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator


def track_inprogress(gauge: Gauge, **labels):
    """Decorator to track in-progress operations"""
    def decorator(func):
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            gauge.labels(**labels).inc()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                gauge.labels(**labels).dec()
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            gauge.labels(**labels).inc()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                gauge.labels(**labels).dec()
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator


class MetricsContext:
    """Context manager for tracking metrics"""
    
    def __init__(self, histogram: Histogram, **labels):
        self.histogram = histogram
        self.labels = labels
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.histogram.labels(**self.labels).observe(duration)
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.histogram.labels(**self.labels).observe(duration)


def get_metrics() -> bytes:
    """Generate metrics in Prometheus format"""
    return generate_latest(metrics_registry)


def get_metrics_content_type() -> str:
    """Get the content type for Prometheus metrics"""
    return CONTENT_TYPE_LATEST


# ====================
# Custom Collectors
# ====================

class RepositoryStatsCollector:
    """Custom collector for repository statistics"""
    
    def __init__(self):
        self.last_update = 0
        self.update_interval = 60  # Update every minute
        self._cached_metrics = []
    
    def collect(self):
        """Collect repository statistics"""
        current_time = time.time()
        
        # Only update if enough time has passed
        if current_time - self.last_update < self.update_interval:
            return self._cached_metrics
        
        # Update metrics (this would scan repositories in production)
        # For now, return empty
        self._cached_metrics = []
        self.last_update = current_time
        
        return self._cached_metrics


# Register custom collectors
# repository_stats_collector = RepositoryStatsCollector()
# metrics_registry.register(repository_stats_collector)