"""Base service class for application services.

This module provides the base class for all application services,
implementing common patterns for initialization, cleanup, and logging.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional
import structlog

logger = structlog.get_logger()

T = TypeVar('T')


class ServiceBase(ABC):
    """Base class for all application services.
    
    Provides common functionality including:
    - Structured logging with service name
    - Resource initialization and cleanup
    - Context manager support for proper lifecycle management
    """
    
    def __init__(self):
        """Initialize the service with a logger bound to the service name."""
        self.logger = logger.bind(service=self.__class__.__name__)
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize service resources.
        
        This method should be called before using the service.
        Implement any necessary setup like connection pooling,
        cache initialization, etc.
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup service resources.
        
        This method should be called when the service is no longer needed.
        Implement cleanup of connections, caches, and other resources.
        """
        pass
    
    async def __aenter__(self):
        """Enter the runtime context and initialize the service."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context and cleanup the service."""
        await self.cleanup()