"""Base plugin interface and types for Git2in plugin system."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime


class PluginPriority(Enum):
    """Plugin execution priority levels."""
    CRITICAL = 0  # Executed first, can block all operations
    HIGH = 10
    NORMAL = 50
    LOW = 100
    BACKGROUND = 1000  # Executed last, non-blocking


class PluginStatus(Enum):
    """Plugin status for result tracking."""
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class PluginMetadata:
    """Plugin metadata information."""
    name: str
    version: str
    author: str
    description: str
    priority: PluginPriority = PluginPriority.NORMAL
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    license: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "priority": self.priority.name,
            "enabled": self.enabled,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "homepage": self.homepage,
            "license": self.license,
        }


@dataclass
class RepositoryInfo:
    """Repository information for plugin context."""
    namespace: str
    name: str
    path: str
    is_bare: bool
    default_branch: Optional[str] = None
    size_bytes: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserInfo:
    """User information for plugin context."""
    id: str
    username: str
    email: str
    role: str
    groups: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OperationData:
    """Operation-specific data for plugin context."""
    operation_type: str  # push, pull, receive, upload
    ref: Optional[str] = None  # Branch or tag reference
    old_sha: Optional[str] = None  # Previous commit SHA
    new_sha: Optional[str] = None  # New commit SHA
    commits: List[Dict[str, Any]] = field(default_factory=list)
    files_changed: List[str] = field(default_factory=list)
    size_bytes: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginContext:
    """Context object passed to plugin methods."""
    repository: RepositoryInfo
    user: UserInfo
    operation: OperationData
    request_id: str
    timestamp: datetime
    config: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "repository": {
                "namespace": self.repository.namespace,
                "name": self.repository.name,
                "path": self.repository.path,
                "is_bare": self.repository.is_bare,
                "default_branch": self.repository.default_branch,
                "size_bytes": self.repository.size_bytes,
                "metadata": self.repository.metadata,
            },
            "user": {
                "id": self.user.id,
                "username": self.user.username,
                "email": self.user.email,
                "role": self.user.role,
                "groups": self.user.groups,
                "permissions": self.user.permissions,
                "metadata": self.user.metadata,
            },
            "operation": {
                "type": self.operation.operation_type,
                "ref": self.operation.ref,
                "old_sha": self.operation.old_sha,
                "new_sha": self.operation.new_sha,
                "commits": self.operation.commits,
                "files_changed": self.operation.files_changed,
                "size_bytes": self.operation.size_bytes,
                "metadata": self.operation.metadata,
            },
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "config": self.config,
            "environment": self.environment,
        }


@dataclass
class PluginResult:
    """Result returned by plugin execution."""
    status: PluginStatus
    allowed: bool = True
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    execution_time_ms: Optional[float] = None
    
    @classmethod
    def success(cls, message: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> "PluginResult":
        """Create a successful result."""
        return cls(
            status=PluginStatus.SUCCESS,
            allowed=True,
            message=message,
            data=data,
        )
    
    @classmethod
    def deny(cls, message: str, data: Optional[Dict[str, Any]] = None) -> "PluginResult":
        """Create a denial result."""
        return cls(
            status=PluginStatus.FAILURE,
            allowed=False,
            message=message,
            data=data,
        )
    
    @classmethod
    def error(cls, message: str, data: Optional[Dict[str, Any]] = None) -> "PluginResult":
        """Create an error result."""
        return cls(
            status=PluginStatus.ERROR,
            allowed=False,
            message=message,
            data=data,
        )
    
    @classmethod
    def skip(cls, message: Optional[str] = None) -> "PluginResult":
        """Create a skipped result."""
        return cls(
            status=PluginStatus.SKIPPED,
            allowed=True,
            message=message,
        )


class Plugin(ABC):
    """Abstract base class for all plugins."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize plugin with configuration.
        
        Args:
            config: Plugin-specific configuration
        """
        self.config = config or {}
        self._metadata: Optional[PluginMetadata] = None
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.
        
        Returns:
            PluginMetadata object with plugin information
        """
        pass
    
    async def initialize(self) -> None:
        """
        Initialize plugin resources.
        
        Called once when the plugin is loaded. Override this method
        to perform any initialization tasks like connecting to databases,
        loading configuration files, etc.
        """
        pass
    
    async def shutdown(self) -> None:
        """
        Clean up plugin resources.
        
        Called when the plugin is being unloaded. Override this method
        to perform cleanup tasks like closing connections, saving state, etc.
        """
        pass
    
    async def validate_config(self) -> bool:
        """
        Validate plugin configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        return True
    
    async def pre_receive(self, context: PluginContext) -> PluginResult:
        """
        Hook called before receiving Git objects.
        
        This is called before any Git objects are received from the client.
        Use this to validate push permissions, check branch protection rules, etc.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult indicating whether to allow the operation
        """
        return PluginResult.skip("pre_receive not implemented")
    
    async def post_receive(self, context: PluginContext) -> PluginResult:
        """
        Hook called after receiving Git objects.
        
        This is called after Git objects have been received and written to disk.
        Use this for notifications, CI/CD triggers, logging, etc.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult with execution status
        """
        return PluginResult.skip("post_receive not implemented")
    
    async def pre_upload(self, context: PluginContext) -> PluginResult:
        """
        Hook called before uploading Git objects.
        
        This is called before sending Git objects to the client.
        Use this to validate pull permissions, implement rate limiting, etc.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult indicating whether to allow the operation
        """
        return PluginResult.skip("pre_upload not implemented")
    
    async def post_upload(self, context: PluginContext) -> PluginResult:
        """
        Hook called after uploading Git objects.
        
        This is called after Git objects have been sent to the client.
        Use this for analytics, logging, bandwidth tracking, etc.
        
        Args:
            context: Plugin execution context
            
        Returns:
            PluginResult with execution status
        """
        return PluginResult.skip("post_upload not implemented")
    
    async def custom_hook(self, hook_name: str, context: PluginContext) -> PluginResult:
        """
        Custom hook for non-standard operations.
        
        This allows plugins to define custom hooks beyond the standard Git operations.
        
        Args:
            hook_name: Name of the custom hook
            context: Plugin execution context
            
        Returns:
            PluginResult with execution status
        """
        return PluginResult.skip(f"custom hook '{hook_name}' not implemented")


# Exception classes for plugin errors

class PluginError(Exception):
    """Base exception for plugin-related errors."""
    pass


class PluginValidationError(PluginError):
    """Raised when plugin validation fails."""
    pass


class PluginRuntimeError(PluginError):
    """Raised when plugin execution encounters an error."""
    pass


class PluginTimeoutError(PluginError):
    """Raised when plugin execution times out."""
    pass


class PluginConfigurationError(PluginError):
    """Raised when plugin configuration is invalid."""
    pass


class PluginDependencyError(PluginError):
    """Raised when plugin dependencies are not met."""
    pass