"""Hook system for repository events"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from src.core.models import Repository, User
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class HookEvent(str, Enum):
    """Types of hook events"""

    PRE_RECEIVE = "pre-receive"
    POST_RECEIVE = "post-receive"
    PRE_UPLOAD = "pre-upload"
    POST_UPLOAD = "post-upload"
    PRE_CLONE = "pre-clone"
    POST_CLONE = "post-clone"
    PRE_PUSH = "pre-push"
    POST_PUSH = "post-push"
    PRE_FETCH = "pre-fetch"
    POST_FETCH = "post-fetch"


class HookContext:
    """Context object passed to hooks"""

    def __init__(
        self,
        event: HookEvent,
        repository: Repository,
        user: Optional[User] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        **kwargs,
    ):
        self.event = event
        self.repository = repository
        self.user = user
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.correlation_id = correlation_id
        self.timestamp = datetime.utcnow()

        # Additional context data
        self.data = kwargs

        # Hook results storage
        self.results: Dict[str, Any] = {}

        # Error tracking
        self.errors: List[str] = []

    def add_result(self, key: str, value: Any) -> None:
        """Add a result from a hook execution"""
        self.results[key] = value

    def add_error(self, error: str) -> None:
        """Add an error message"""
        self.errors.append(error)

    def has_errors(self) -> bool:
        """Check if any errors occurred"""
        return len(self.errors) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary"""
        return {
            "event": self.event.value,
            "repository": self.repository.full_name,
            "user": self.user.username if self.user else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "results": self.results,
            "errors": self.errors,
        }


class Hook(ABC):
    """Base class for hooks"""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    async def execute(self, context: HookContext) -> None:
        """Execute the hook with given context"""
        pass

    def should_run(self, context: HookContext) -> bool:
        """Check if hook should run for given context"""
        return self.enabled


class LoggingHook(Hook):
    """Built-in hook for logging repository events"""

    def __init__(self):
        super().__init__("logging", enabled=True)

    async def execute(self, context: HookContext) -> None:
        """Log the repository event"""
        logger.info(
            "repository_hook_event",
            hook_event=context.event.value,
            repository=context.repository.full_name,
            user=context.user.username if context.user else None,
            ip_address=context.ip_address,
            correlation_id=context.correlation_id,
            data=context.data,
        )


class StatisticsHook(Hook):
    """Built-in hook for updating repository statistics"""

    def __init__(self):
        super().__init__("statistics", enabled=True)
        self.stats: Dict[str, int] = {}

    async def execute(self, context: HookContext) -> None:
        """Update repository statistics"""
        stat_key = f"{context.repository.full_name}:{context.event.value}"

        if stat_key not in self.stats:
            self.stats[stat_key] = 0
        self.stats[stat_key] += 1

        # Add stats to context results
        context.add_result(
            "statistics",
            {
                "event_count": self.stats[stat_key],
                "total_events": sum(self.stats.values()),
            },
        )

        logger.debug(
            "repository_statistics_updated",
            repository=context.repository.full_name,
            event=context.event.value,
            count=self.stats[stat_key],
        )


class AccessControlHook(Hook):
    """Built-in hook for access control validation"""

    def __init__(self, check_function: Optional[Callable] = None):
        super().__init__("access_control", enabled=True)
        self.check_function = check_function

    async def execute(self, context: HookContext) -> None:
        """Check access permissions"""
        if not self.check_function:
            return

        # Run access check
        try:
            allowed = await self.check_function(context)

            if not allowed:
                context.add_error("Access denied by access control hook")
                logger.warning(
                    "access_denied_by_hook",
                    repository=context.repository.full_name,
                    user=context.user.username if context.user else None,
                    event=context.event.value,
                )
        except Exception as e:
            logger.error(
                "access_control_hook_error",
                error=str(e),
                repository=context.repository.full_name,
            )
            context.add_error(f"Access control error: {str(e)}")


class WebhookHook(Hook):
    """Hook for calling external webhooks"""

    def __init__(self, url: str, timeout: float = 10.0):
        super().__init__("webhook", enabled=True)
        self.url = url
        self.timeout = timeout

    async def execute(self, context: HookContext) -> None:
        """Call external webhook"""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.url,
                    json=context.to_dict(),
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code >= 400:
                    context.add_error(f"Webhook returned status {response.status_code}")
                else:
                    context.add_result(
                        "webhook_response",
                        {
                            "status": response.status_code,
                            "body": response.text[:1000],  # Limit response size
                        },
                    )

        except Exception as e:
            logger.error("webhook_hook_error", url=self.url, error=str(e))
            context.add_error(f"Webhook error: {str(e)}")


class HookManager:
    """Manages hook registration and execution"""

    def __init__(self):
        self.hooks: Dict[HookEvent, List[Hook]] = {event: [] for event in HookEvent}

        # Register built-in hooks
        self._register_builtin_hooks()

    def _register_builtin_hooks(self) -> None:
        """Register built-in hooks"""
        # Add logging hook to all events
        logging_hook = LoggingHook()
        for event in HookEvent:
            self.register_hook(event, logging_hook)

        # Add statistics hook to key events
        stats_hook = StatisticsHook()
        for event in [HookEvent.POST_RECEIVE, HookEvent.POST_UPLOAD]:
            self.register_hook(event, stats_hook)

    def register_hook(self, event: HookEvent, hook: Hook) -> None:
        """Register a hook for an event"""
        if hook not in self.hooks[event]:
            self.hooks[event].append(hook)
            logger.info("hook_registered", hook_event=event.value, hook_name=hook.name)

    def unregister_hook(self, event: HookEvent, hook: Hook) -> None:
        """Unregister a hook from an event"""
        if hook in self.hooks[event]:
            self.hooks[event].remove(hook)
            logger.info(
                "hook_unregistered", hook_event=event.value, hook_name=hook.name
            )

    async def execute_hooks(
        self,
        event: HookEvent,
        context: HookContext,
        timeout: float = 30.0,
        stop_on_error: bool = False,
    ) -> HookContext:
        """Execute all hooks for an event"""

        hooks = self.hooks.get(event, [])

        logger.debug(
            "executing_hooks",
            event=event.value,
            hook_count=len(hooks),
            repository=context.repository.full_name,
        )

        for hook in hooks:
            if not hook.should_run(context):
                continue

            try:
                # Execute hook with timeout
                await asyncio.wait_for(hook.execute(context), timeout=timeout)

                logger.debug("hook_executed", event=event.value, hook=hook.name)

            except asyncio.TimeoutError:
                error_msg = f"Hook '{hook.name}' timed out"
                context.add_error(error_msg)
                logger.error(
                    "hook_timeout", event=event.value, hook=hook.name, timeout=timeout
                )

                if stop_on_error:
                    break

            except Exception as e:
                error_msg = f"Hook '{hook.name}' failed: {str(e)}"
                context.add_error(error_msg)
                logger.error(
                    "hook_error", event=event.value, hook=hook.name, error=str(e)
                )

                if stop_on_error:
                    break

        return context

    def get_hooks(self, event: HookEvent) -> List[Hook]:
        """Get all hooks for an event"""
        return self.hooks.get(event, [])

    def clear_hooks(self, event: Optional[HookEvent] = None) -> None:
        """Clear hooks for an event or all events"""
        if event:
            self.hooks[event] = []
        else:
            for event in HookEvent:
                self.hooks[event] = []


# Global hook manager instance
hook_manager = HookManager()
