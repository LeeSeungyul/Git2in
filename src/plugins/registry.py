"""Plugin registry for managing loaded plugins."""

from typing import Dict, List, Optional, Set

import structlog

from src.plugins.base import Plugin, PluginMetadata, PluginPriority

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """Registry for managing loaded plugins."""

    def __init__(self):
        """Initialize plugin registry."""
        self._plugins: Dict[str, Plugin] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
        self._priority_groups: Dict[PluginPriority, List[str]] = {
            priority: [] for priority in PluginPriority
        }
        self._tags: Dict[str, Set[str]] = {}

    def register(self, plugin: Plugin) -> None:
        """
        Register a plugin.

        Args:
            plugin: Plugin instance to register

        Raises:
            ValueError: If plugin with same name already registered
        """
        metadata = plugin.metadata

        if metadata.name in self._plugins:
            raise ValueError(f"Plugin already registered: {metadata.name}")

        self._plugins[metadata.name] = plugin
        self._metadata[metadata.name] = metadata

        # Add to priority group
        self._priority_groups[metadata.priority].append(metadata.name)

        # Index by tags
        for tag in metadata.tags:
            if tag not in self._tags:
                self._tags[tag] = set()
            self._tags[tag].add(metadata.name)

        logger.info(
            "Registered plugin",
            name=metadata.name,
            version=metadata.version,
            priority=metadata.priority.name,
        )

    def unregister(self, plugin_name: str) -> Optional[Plugin]:
        """
        Unregister a plugin.

        Args:
            plugin_name: Name of plugin to unregister

        Returns:
            Unregistered plugin instance or None if not found
        """
        if plugin_name not in self._plugins:
            return None

        plugin = self._plugins.pop(plugin_name)
        metadata = self._metadata.pop(plugin_name)

        # Remove from priority group
        self._priority_groups[metadata.priority].remove(plugin_name)

        # Remove from tag index
        for tag in metadata.tags:
            if tag in self._tags:
                self._tags[tag].discard(plugin_name)
                if not self._tags[tag]:
                    del self._tags[tag]

        logger.info("Unregistered plugin", name=plugin_name)
        return plugin

    def get(self, plugin_name: str) -> Optional[Plugin]:
        """
        Get a plugin by name.

        Args:
            plugin_name: Name of plugin to get

        Returns:
            Plugin instance or None if not found
        """
        return self._plugins.get(plugin_name)

    def get_metadata(self, plugin_name: str) -> Optional[PluginMetadata]:
        """
        Get plugin metadata by name.

        Args:
            plugin_name: Name of plugin

        Returns:
            Plugin metadata or None if not found
        """
        return self._metadata.get(plugin_name)

    def list_plugins(self) -> List[str]:
        """
        List all registered plugin names.

        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())

    def get_enabled_plugins(self) -> List[Plugin]:
        """
        Get all enabled plugins sorted by priority.

        Returns:
            List of enabled plugins
        """
        enabled = []

        for priority in PluginPriority:
            for plugin_name in self._priority_groups[priority]:
                metadata = self._metadata[plugin_name]
                if metadata.enabled:
                    enabled.append(self._plugins[plugin_name])

        return enabled

    def get_plugins_by_priority(self, priority: PluginPriority) -> List[Plugin]:
        """
        Get plugins with specific priority.

        Args:
            priority: Priority level to filter by

        Returns:
            List of plugins with given priority
        """
        plugins = []
        for plugin_name in self._priority_groups[priority]:
            plugins.append(self._plugins[plugin_name])
        return plugins

    def get_plugins_by_tag(self, tag: str) -> List[Plugin]:
        """
        Get plugins with specific tag.

        Args:
            tag: Tag to filter by

        Returns:
            List of plugins with given tag
        """
        if tag not in self._tags:
            return []

        plugins = []
        for plugin_name in self._tags[tag]:
            plugins.append(self._plugins[plugin_name])
        return plugins

    def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin.

        Args:
            plugin_name: Name of plugin to enable

        Returns:
            True if plugin was enabled, False if not found
        """
        if plugin_name in self._metadata:
            self._metadata[plugin_name].enabled = True
            logger.info("Enabled plugin", name=plugin_name)
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin.

        Args:
            plugin_name: Name of plugin to disable

        Returns:
            True if plugin was disabled, False if not found
        """
        if plugin_name in self._metadata:
            self._metadata[plugin_name].enabled = False
            logger.info("Disabled plugin", name=plugin_name)
            return True
        return False

    def clear(self) -> None:
        """Clear all registered plugins."""
        self._plugins.clear()
        self._metadata.clear()
        for priority_list in self._priority_groups.values():
            priority_list.clear()
        self._tags.clear()
        logger.info("Cleared plugin registry")
