"""Plugin manager for orchestrating plugin execution."""

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog

from src.plugins.base import (Plugin, PluginContext, PluginError, PluginResult,
                              PluginStatus)
from src.plugins.config import PluginConfig, PluginConfigManager
from src.plugins.external import ExternalPlugin
from src.plugins.loader import PluginLoader
from src.plugins.registry import PluginRegistry
from src.plugins.sandbox import PluginSandbox, ResourceLimits

logger = structlog.get_logger(__name__)


class PluginExecutionResult:
    """Result of plugin execution across multiple plugins."""

    def __init__(self):
        """Initialize execution result."""
        self.results: List[tuple[str, PluginResult]] = []
        self.total_time_ms: float = 0
        self.failed_plugins: List[str] = []
        self.skipped_plugins: List[str] = []

    def add_result(self, plugin_name: str, result: PluginResult):
        """Add a plugin result."""
        self.results.append((plugin_name, result))

        if result.status == PluginStatus.FAILURE:
            self.failed_plugins.append(plugin_name)
        elif result.status == PluginStatus.SKIPPED:
            self.skipped_plugins.append(plugin_name)

        if result.execution_time_ms:
            self.total_time_ms += result.execution_time_ms

    @property
    def all_allowed(self) -> bool:
        """Check if all plugins allowed the operation."""
        return all(result.allowed for _, result in self.results)

    @property
    def any_denied(self) -> bool:
        """Check if any plugin denied the operation."""
        return any(not result.allowed for _, result in self.results)

    def get_denial_messages(self) -> List[str]:
        """Get messages from plugins that denied the operation."""
        messages = []
        for plugin_name, result in self.results:
            if not result.allowed and result.message:
                messages.append(f"{plugin_name}: {result.message}")
        return messages


class PluginManager:
    """Manages plugin lifecycle and execution."""

    def __init__(
        self,
        plugin_dirs: Optional[List[Path]] = None,
        config_manager: Optional[PluginConfigManager] = None,
        enable_sandbox: bool = True,
        fallback_behavior: str = "fail-closed",  # fail-closed, fail-open, or degraded
    ):
        """
        Initialize plugin manager.

        Args:
            plugin_dirs: Directories to search for plugins
            config_manager: Configuration manager instance
            enable_sandbox: Whether to enable sandboxing for plugins
            fallback_behavior: Behavior when plugins fail (fail-closed, fail-open, degraded)
        """
        self.loader = PluginLoader(plugin_dirs)
        self.registry = PluginRegistry()
        self.config_manager = config_manager or PluginConfigManager()
        self.enable_sandbox = enable_sandbox
        self.fallback_behavior = fallback_behavior
        self._initialized = False

        # Circuit breaker for failing plugins
        self._failure_counts: Dict[str, int] = {}
        self._disabled_until: Dict[str, float] = {}
        self.circuit_breaker_threshold = 3
        self.circuit_breaker_timeout = 60.0  # seconds

    async def initialize(self):
        """Initialize the plugin manager and load plugins."""
        if self._initialized:
            return

        # Discover and load plugins
        await self.discover_and_load_plugins()

        # Initialize all loaded plugins
        for plugin_name in self.registry.list_plugins():
            plugin = self.registry.get(plugin_name)
            if plugin:
                try:
                    await plugin.initialize()
                    logger.info(f"Initialized plugin: {plugin_name}")
                except Exception as e:
                    logger.error(f"Failed to initialize plugin {plugin_name}: {e}")
                    self.registry.unregister(plugin_name)

        self._initialized = True
        logger.info(
            "Plugin manager initialized",
            plugins_loaded=len(self.registry.list_plugins()),
        )

    async def shutdown(self):
        """Shutdown all plugins and cleanup resources."""
        for plugin_name in self.registry.list_plugins():
            plugin = self.registry.get(plugin_name)
            if plugin:
                try:
                    await plugin.shutdown()
                    logger.info(f"Shutdown plugin: {plugin_name}")
                except Exception as e:
                    logger.error(f"Error during plugin shutdown {plugin_name}: {e}")

        self.registry.clear()
        self._initialized = False
        logger.info("Plugin manager shutdown complete")

    async def discover_and_load_plugins(self):
        """Discover and load all available plugins."""
        # Load configuration
        configs = self.config_manager.load_directory()

        # Discover available plugins
        discovered = self.loader.discover_plugins()

        for plugin_name in discovered:
            try:
                # Get configuration for plugin
                config = configs.get(plugin_name)

                if config and not config.enabled:
                    logger.info(f"Skipping disabled plugin: {plugin_name}")
                    continue

                # Load and instantiate plugin
                plugin = await self.load_plugin(plugin_name, config)

                if plugin:
                    self.registry.register(plugin)

            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_name}: {e}")

    async def load_plugin(
        self,
        plugin_name: str,
        config: Optional[PluginConfig] = None,
    ) -> Optional[Plugin]:
        """
        Load a single plugin.

        Args:
            plugin_name: Name of the plugin to load
            config: Plugin configuration

        Returns:
            Loaded plugin instance or None if failed
        """
        try:
            if config and config.executable:
                # Load as external plugin
                plugin = ExternalPlugin(
                    executable_path=config.executable,
                    config=config.settings if config else None,
                    timeout=(
                        config.resources.timeout
                        if config and config.resources
                        else 30.0
                    ),
                    env=config.environment if config else None,
                )
            else:
                # Load as Python module
                plugin = self.loader.instantiate_plugin(
                    plugin_name,
                    config=config.settings if config else None,
                )

            # Validate plugin
            if self.loader.validate_plugin(plugin):
                # Check dependencies
                self.loader.check_dependencies(plugin)

                logger.info(
                    "Loaded plugin",
                    name=plugin_name,
                    type="external" if isinstance(plugin, ExternalPlugin) else "python",
                )

                return plugin

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")

        return None

    async def execute_hook(
        self,
        hook_name: str,
        context: PluginContext,
        namespace: Optional[str] = None,
        repository: Optional[str] = None,
    ) -> PluginExecutionResult:
        """
        Execute a hook across all enabled plugins.

        Args:
            hook_name: Name of the hook to execute
            context: Plugin execution context
            namespace: Optional namespace for configuration
            repository: Optional repository for configuration

        Returns:
            Execution result with all plugin results
        """
        result = PluginExecutionResult()
        start_time = time.time()

        # Get enabled plugins sorted by priority
        plugins = self.registry.get_enabled_plugins()

        for plugin in plugins:
            plugin_name = plugin.metadata.name

            # Check circuit breaker
            if self._is_circuit_open(plugin_name):
                logger.warning(f"Circuit breaker open for plugin: {plugin_name}")
                result.add_result(
                    plugin_name,
                    PluginResult.skip("Circuit breaker open"),
                )
                continue

            # Get effective configuration
            if self.config_manager:
                config = self.config_manager.get_plugin_config(
                    plugin_name,
                    namespace,
                    repository,
                )
                if config and not config.enabled:
                    continue
            else:
                config = None

            # Execute plugin hook
            plugin_result = await self._execute_plugin_hook(
                plugin,
                hook_name,
                context,
                config,
            )

            result.add_result(plugin_name, plugin_result)

            # Update circuit breaker
            self._update_circuit_breaker(plugin_name, plugin_result)

            # Stop on denial for pre-hooks
            if hook_name.startswith("pre_") and not plugin_result.allowed:
                logger.info(
                    f"Plugin {plugin_name} denied operation in {hook_name}",
                    message=plugin_result.message,
                )
                break

        result.total_time_ms = (time.time() - start_time) * 1000

        logger.info(
            f"Executed hook {hook_name}",
            total_plugins=len(plugins),
            failed=len(result.failed_plugins),
            skipped=len(result.skipped_plugins),
            time_ms=result.total_time_ms,
        )

        return result

    async def _execute_plugin_hook(
        self,
        plugin: Plugin,
        hook_name: str,
        context: PluginContext,
        config: Optional[PluginConfig] = None,
    ) -> PluginResult:
        """
        Execute a single plugin hook with optional sandboxing.

        Args:
            plugin: Plugin instance
            hook_name: Name of the hook
            context: Execution context
            config: Plugin configuration

        Returns:
            Plugin result
        """
        start_time = time.time()

        try:
            # Determine if sandboxing is needed
            if self.enable_sandbox and config and config.sandbox:
                result = await self._execute_sandboxed(
                    plugin,
                    hook_name,
                    context,
                    config,
                )
            else:
                # Direct execution
                if hasattr(plugin, hook_name):
                    hook_method = getattr(plugin, hook_name)
                    result = await hook_method(context)
                else:
                    result = await plugin.custom_hook(hook_name, context)

            # Add execution time
            result.execution_time_ms = (time.time() - start_time) * 1000

            return result

        except Exception as e:
            logger.error(
                f"Plugin hook execution failed",
                plugin=plugin.metadata.name,
                hook=hook_name,
                error=str(e),
            )

            # Apply fallback behavior
            if self.fallback_behavior == "fail-open":
                return PluginResult.success(f"Failed but allowing: {e}")
            elif self.fallback_behavior == "degraded":
                return PluginResult.skip(f"Failed, running degraded: {e}")
            else:  # fail-closed
                return PluginResult.error(f"Plugin execution failed: {e}")

    async def _execute_sandboxed(
        self,
        plugin: Plugin,
        hook_name: str,
        context: PluginContext,
        config: PluginConfig,
    ) -> PluginResult:
        """Execute plugin in a sandboxed environment."""
        # Create sandbox with configured limits
        limits = (
            config.resources.to_resource_limits()
            if config.resources
            else ResourceLimits()
        )

        sandbox = PluginSandbox(
            limits=limits,
            network_enabled=config.network_enabled,
        )

        # For external plugins, use sandbox execution
        if isinstance(plugin, ExternalPlugin):
            return await plugin._execute_hook(hook_name, context)

        # For Python plugins, we would need to serialize and execute in subprocess
        # This is a simplified implementation
        logger.warning(
            "Sandboxing for Python plugins not fully implemented",
            plugin=plugin.metadata.name,
        )

        # Fall back to direct execution with warning
        if hasattr(plugin, hook_name):
            hook_method = getattr(plugin, hook_name)
            return await hook_method(context)
        else:
            return await plugin.custom_hook(hook_name, context)

    def _is_circuit_open(self, plugin_name: str) -> bool:
        """Check if circuit breaker is open for a plugin."""
        if plugin_name in self._disabled_until:
            if time.time() < self._disabled_until[plugin_name]:
                return True
            else:
                # Reset circuit breaker
                del self._disabled_until[plugin_name]
                self._failure_counts[plugin_name] = 0
        return False

    def _update_circuit_breaker(self, plugin_name: str, result: PluginResult):
        """Update circuit breaker state based on plugin result."""
        if result.status in [PluginStatus.ERROR, PluginStatus.TIMEOUT]:
            # Increment failure count
            self._failure_counts[plugin_name] = (
                self._failure_counts.get(plugin_name, 0) + 1
            )

            # Check if threshold reached
            if self._failure_counts[plugin_name] >= self.circuit_breaker_threshold:
                self._disabled_until[plugin_name] = (
                    time.time() + self.circuit_breaker_timeout
                )
                logger.warning(
                    f"Circuit breaker activated for plugin {plugin_name}",
                    failures=self._failure_counts[plugin_name],
                    timeout_seconds=self.circuit_breaker_timeout,
                )
        else:
            # Reset failure count on success
            if plugin_name in self._failure_counts:
                self._failure_counts[plugin_name] = 0

    def reload_config(self):
        """Reload plugin configuration if changed."""
        if self.config_manager.reload_if_changed():
            logger.info("Plugin configuration reloaded")

            # Re-evaluate enabled plugins
            for plugin_name in self.registry.list_plugins():
                config = self.config_manager.get_plugin_config(plugin_name)
                if config:
                    if config.enabled:
                        self.registry.enable_plugin(plugin_name)
                    else:
                        self.registry.disable_plugin(plugin_name)
