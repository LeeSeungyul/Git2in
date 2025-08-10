"""Custom structlog processors for enhanced logging"""

from typing import Any, Dict, Optional, MutableMapping
import structlog
from structlog.types import EventDict, WrappedLogger
from structlog.contextvars import get_contextvars


def add_service_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add service-level context to logs"""
    # Add service name
    event_dict["service"] = "git2in"
    
    # Add environment
    from src.core.config import settings
    event_dict["environment"] = settings.environment
    
    # Add hostname if available
    import socket
    try:
        event_dict["hostname"] = socket.gethostname()
    except:
        pass
    
    return event_dict


def add_request_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add request-specific context from contextvars"""
    context = get_contextvars()
    
    # Add correlation ID if present
    if "correlation_id" in context:
        event_dict["correlation_id"] = context["correlation_id"]
    
    # Add user context if present
    if "user_id" in context:
        event_dict["user_id"] = context["user_id"]
    if "username" in context:
        event_dict["username"] = context["username"]
    
    # Add request metadata if present
    if "request_method" in context:
        event_dict["request_method"] = context["request_method"]
    if "request_path" in context:
        event_dict["request_path"] = context["request_path"]
    if "client_ip" in context:
        event_dict["client_ip"] = context["client_ip"]
    
    # Add namespace/repository context if present
    if "namespace" in context:
        event_dict["namespace"] = context["namespace"]
    if "repository" in context:
        event_dict["repository"] = context["repository"]
    
    return event_dict


def sanitize_sensitive_data(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Remove or mask sensitive data from logs"""
    sensitive_keys = {
        "password", "token", "secret", "api_key", "authorization",
        "private_key", "access_token", "refresh_token", "bearer"
    }
    
    def sanitize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary"""
        sanitized = {}
        for key, value in d.items():
            lower_key = key.lower()
            
            # Check if key contains sensitive words
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    sanitize_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    return sanitize_dict(event_dict)


def add_caller_info(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add caller location information for debugging"""
    # Only add in development mode
    from src.core.config import settings
    if not settings.is_development:
        return event_dict
    
    import inspect
    
    # Get the frame of the actual caller (skip structlog frames)
    frame = None
    for record in inspect.stack()[1:]:
        module = inspect.getmodule(record.frame)
        if module and not module.__name__.startswith("structlog"):
            frame = record
            break
    
    if frame:
        event_dict["caller"] = {
            "filename": frame.filename.split("/")[-1],
            "function": frame.function,
            "lineno": frame.lineno
        }
    
    return event_dict


def format_exception_info(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Format exception information for better readability"""
    import sys
    import traceback
    
    exc_info = event_dict.pop("exc_info", None)
    if exc_info:
        if isinstance(exc_info, tuple):
            exc_type, exc_value, exc_tb = exc_info
        else:
            exc_type, exc_value, exc_tb = sys.exc_info()
        
        if exc_type:
            event_dict["exception"] = {
                "type": exc_type.__name__,
                "message": str(exc_value),
                "traceback": traceback.format_exception(exc_type, exc_value, exc_tb)
            }
    
    return event_dict


def set_log_severity(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Set proper severity field for log aggregation systems"""
    # Map Python log levels to standard severity levels
    level_map = {
        "debug": "DEBUG",
        "info": "INFO",
        "warning": "WARNING",
        "error": "ERROR",
        "critical": "CRITICAL"
    }
    
    if "level" in event_dict:
        event_dict["severity"] = level_map.get(event_dict["level"], "INFO")
    
    return event_dict


class MetricsProcessor:
    """Processor that collects metrics about logging"""
    
    def __init__(self):
        self.log_counter = None
    
    def __call__(
        self, logger: WrappedLogger, method_name: str, event_dict: EventDict
    ) -> EventDict:
        """Count log messages by level"""
        # Lazy import to avoid circular dependency
        try:
            from src.infrastructure.metrics import log_messages_total
            
            if log_messages_total and "level" in event_dict:
                log_messages_total.labels(
                    level=event_dict["level"],
                    logger=logger.name if hasattr(logger, "name") else "unknown"
                ).inc()
        except ImportError:
            pass
        
        return event_dict