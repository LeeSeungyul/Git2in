"""Structured audit logging system"""

import json
import logging
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
from enum import Enum
import time
from uuid import UUID

from src.core.config import settings
from src.infrastructure.middleware.correlation import get_correlation_id

# Audit log levels
class AuditLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditAction(str, Enum):
    """Audit action types"""
    # Git operations
    CLONE = "clone"
    PULL = "pull"
    PUSH = "push"
    FETCH = "fetch"
    
    # Repository operations
    CREATE_REPO = "create_repo"
    DELETE_REPO = "delete_repo"
    UPDATE_REPO = "update_repo"
    
    # Namespace operations
    CREATE_NAMESPACE = "create_namespace"
    DELETE_NAMESPACE = "delete_namespace"
    UPDATE_NAMESPACE = "update_namespace"
    
    # User operations
    CREATE_USER = "create_user"
    DELETE_USER = "delete_user"
    UPDATE_USER = "update_user"
    LOGIN = "login"
    LOGOUT = "logout"
    
    # Token operations
    CREATE_TOKEN = "create_token"
    REVOKE_TOKEN = "revoke_token"
    REFRESH_TOKEN = "refresh_token"
    
    # Permission operations
    GRANT_PERMISSION = "grant_permission"
    REVOKE_PERMISSION = "revoke_permission"
    
    # System operations
    VIEW_LOGS = "view_logs"
    VIEW_METRICS = "view_metrics"
    SYSTEM_CONFIG = "system_config"


class AuditResult(str, Enum):
    """Result of audited action"""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class AuditLogFormatter(logging.Formatter):
    """Custom formatter for audit logs"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "action": getattr(record, "action", "unknown"),
            "result": getattr(record, "result", "unknown"),
            "user_id": getattr(record, "user_id", None),
            "user_email": getattr(record, "user_email", None),
            "resource": getattr(record, "resource", None),
            "resource_type": getattr(record, "resource_type", None),
            "client_ip": getattr(record, "client_ip", None),
            "user_agent": getattr(record, "user_agent", None),
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "duration_ms": getattr(record, "duration_ms", None),
            "details": getattr(record, "details", {}),
            "error": getattr(record, "error", None)
        }
        
        # Remove None values
        log_data = {k: v for k, v in log_data.items() if v is not None}
        
        return json.dumps(log_data, default=str)


class AsyncAuditHandler(logging.Handler):
    """Async handler for non-blocking audit logging"""
    
    def __init__(self, base_handler: logging.Handler):
        super().__init__()
        self.base_handler = base_handler
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the async worker"""
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._worker())
    
    async def stop(self):
        """Stop the async worker"""
        self._running = False
        if self._task:
            await self._queue.put(None)  # Sentinel to stop worker
            await self._task
    
    async def _worker(self):
        """Worker to process log records"""
        while self._running:
            try:
                record = await self._queue.get()
                if record is None:  # Sentinel
                    break
                
                # Process record in base handler
                self.base_handler.emit(record)
                
            except Exception as e:
                # Log to stderr if audit logging fails
                import sys
                print(f"Audit logging error: {e}", file=sys.stderr)
    
    def emit(self, record: logging.LogRecord):
        """Queue record for async processing"""
        try:
            # Non-blocking put
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            # Fall back to synchronous logging if queue is full
            self.base_handler.emit(record)


class AuditLogger:
    """Main audit logger service"""
    
    def __init__(self):
        self._logger = self._setup_logger()
        self._async_handler: Optional[AsyncAuditHandler] = None
        self._start_time: Dict[str, float] = {}
    
    def _setup_logger(self) -> logging.Logger:
        """Setup audit logger with appropriate handlers"""
        logger = logging.getLogger("audit")
        logger.setLevel(logging.INFO)
        logger.propagate = False  # Don't propagate to root logger
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # Create audit log directory
        log_dir = Path("logs/audit")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler with rotation
        from logging.handlers import TimedRotatingFileHandler
        
        file_handler = TimedRotatingFileHandler(
            filename=log_dir / "audit.log",
            when="midnight",
            interval=1,
            backupCount=90,  # Keep 90 days by default
            encoding="utf-8"
        )
        file_handler.setFormatter(AuditLogFormatter())
        
        # Wrap in async handler if in production
        if settings.is_production:
            self._async_handler = AsyncAuditHandler(file_handler)
            logger.addHandler(self._async_handler)
        else:
            logger.addHandler(file_handler)
        
        # Also log to console in development
        if settings.is_development:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(AuditLogFormatter())
            logger.addHandler(console_handler)
        
        return logger
    
    async def start(self):
        """Start async logging"""
        if self._async_handler:
            await self._async_handler.start()
    
    async def stop(self):
        """Stop async logging"""
        if self._async_handler:
            await self._async_handler.stop()
    
    def log(
        self,
        action: AuditAction,
        result: AuditResult,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        resource: Optional[str] = None,
        resource_type: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        level: AuditLevel = AuditLevel.INFO
    ):
        """Log an audit event"""
        
        # Determine log level
        if result == AuditResult.SUCCESS:
            log_level = logging.INFO
        elif result == AuditResult.DENIED:
            log_level = logging.WARNING
        elif result in [AuditResult.FAILURE, AuditResult.ERROR]:
            log_level = logging.ERROR
        else:
            log_level = logging.INFO
        
        # Override with explicit level if provided
        if level == AuditLevel.WARNING:
            log_level = logging.WARNING
        elif level == AuditLevel.ERROR:
            log_level = logging.ERROR
        elif level == AuditLevel.CRITICAL:
            log_level = logging.CRITICAL
        
        # Create log record
        extra = {
            "action": action.value,
            "result": result.value,
            "user_id": user_id,
            "user_email": user_email,
            "resource": resource,
            "resource_type": resource_type,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "correlation_id": correlation_id or get_correlation_id(),
            "duration_ms": duration_ms,
            "details": details or {},
            "error": error
        }
        
        self._logger.log(
            log_level,
            f"{action.value} {result.value}",
            extra=extra
        )
    
    def start_operation(self, operation_id: str):
        """Start timing an operation"""
        self._start_time[operation_id] = time.time()
    
    def end_operation(self, operation_id: str) -> Optional[int]:
        """End timing an operation and return duration in ms"""
        if operation_id in self._start_time:
            duration = (time.time() - self._start_time[operation_id]) * 1000
            del self._start_time[operation_id]
            return int(duration)
        return None
    
    def log_success(
        self,
        action: AuditAction,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs
    ):
        """Log a successful action"""
        self.log(
            action=action,
            result=AuditResult.SUCCESS,
            user_id=user_id,
            resource=resource,
            **kwargs
        )
    
    def log_failure(
        self,
        action: AuditAction,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        error: Optional[str] = None,
        **kwargs
    ):
        """Log a failed action"""
        self.log(
            action=action,
            result=AuditResult.FAILURE,
            user_id=user_id,
            resource=resource,
            error=error,
            level=AuditLevel.ERROR,
            **kwargs
        )
    
    def log_denied(
        self,
        action: AuditAction,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        reason: Optional[str] = None,
        **kwargs
    ):
        """Log a denied action"""
        self.log(
            action=action,
            result=AuditResult.DENIED,
            user_id=user_id,
            resource=resource,
            details={"denial_reason": reason} if reason else None,
            level=AuditLevel.WARNING,
            **kwargs
        )
    
    def log_error(
        self,
        action: AuditAction,
        error: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs
    ):
        """Log an error during action"""
        self.log(
            action=action,
            result=AuditResult.ERROR,
            user_id=user_id,
            resource=resource,
            error=error,
            level=AuditLevel.ERROR,
            **kwargs
        )


# Global audit logger instance
audit_logger = AuditLogger()