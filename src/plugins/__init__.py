"""Git2in Plugin System.

This module provides an extensible plugin architecture for Git2in,
allowing custom hooks to be executed during various Git operations.
"""

from src.plugins.base import (
    Plugin,
    PluginMetadata,
    PluginResult,
    PluginContext,
    PluginError,
    PluginValidationError,
    PluginRuntimeError,
    PluginTimeoutError,
)
from src.plugins.loader import PluginLoader
from src.plugins.manager import PluginManager
from src.plugins.registry import PluginRegistry

__all__ = [
    "Plugin",
    "PluginMetadata",
    "PluginResult",
    "PluginContext",
    "PluginError",
    "PluginValidationError",
    "PluginRuntimeError",
    "PluginTimeoutError",
    "PluginLoader",
    "PluginManager",
    "PluginRegistry",
]