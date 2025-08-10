import logging
import sys
from typing import Any, Dict, Optional
import structlog
from structlog.types import Processor
import json

from src.core.config import settings
from src.infrastructure.logging_processors import (
    add_service_context,
    add_request_context,
    sanitize_sensitive_data,
    add_caller_info,
    format_exception_info,
    set_log_severity,
    MetricsProcessor
)


def setup_logging() -> None:
    timestamper = structlog.processors.TimeStamper(fmt="iso")
    
    # Build processor chain
    shared_processors: list[Processor] = [
        # Add contextvars (correlation ID, user context, etc.)
        structlog.contextvars.merge_contextvars,
        
        # Add custom context
        add_service_context,
        add_request_context,
        
        # Add log level
        structlog.processors.add_log_level,
        set_log_severity,
        
        # Add caller info in development
        add_caller_info if settings.is_development else lambda *args: args[-1],
        
        # Format exceptions
        format_exception_info,
        
        # Add timestamp
        timestamper,
        
        # Sanitize sensitive data (should be last before rendering)
        sanitize_sensitive_data,
        
        # Collect metrics
        MetricsProcessor(),
    ]
    
    if settings.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.rich_traceback
        )
    
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, settings.log_level))
    
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, settings.log_level))
        logger.propagate = False


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


def bind_context(**kwargs: Any) -> None:
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()


def unbind_context(*keys: str) -> None:
    structlog.contextvars.unbind_contextvars(*keys)