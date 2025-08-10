"""Plugin loader for dynamically loading Python modules and external plugins."""

import importlib
import importlib.util
import inspect
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union
import structlog

from src.plugins.base import (
    Plugin,
    PluginError,
    PluginValidationError,
    PluginDependencyError,
)

logger = structlog.get_logger(__name__)


class PluginLoader:
    """Loads and manages plugin modules."""
    
    def __init__(self, plugin_dirs: Optional[List[Union[str, Path]]] = None):
        """
        Initialize plugin loader.
        
        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self.plugin_dirs = []
        if plugin_dirs:
            for dir_path in plugin_dirs:
                self.add_plugin_directory(dir_path)
        
        # Add default plugin directories
        default_dirs = [
            Path(__file__).parent / "builtin",
            Path("/etc/git2in/plugins"),
            Path.home() / ".git2in/plugins",
        ]
        
        for dir_path in default_dirs:
            if dir_path.exists() and dir_path.is_dir():
                self.plugin_dirs.append(dir_path)
        
        self._loaded_modules: Dict[str, Any] = {}
        self._plugin_classes: Dict[str, Type[Plugin]] = {}
    
    def add_plugin_directory(self, directory: Union[str, Path]) -> None:
        """
        Add a directory to search for plugins.
        
        Args:
            directory: Path to plugin directory
            
        Raises:
            ValueError: If directory doesn't exist or isn't a directory
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            raise ValueError(f"Plugin directory does not exist: {directory}")
        if not dir_path.is_dir():
            raise ValueError(f"Plugin path is not a directory: {directory}")
        
        if dir_path not in self.plugin_dirs:
            self.plugin_dirs.append(dir_path)
            # Add to Python path for imports
            if str(dir_path) not in sys.path:
                sys.path.insert(0, str(dir_path))
    
    def discover_plugins(self) -> List[str]:
        """
        Discover available plugins in configured directories.
        
        Returns:
            List of discovered plugin names
        """
        discovered = []
        
        for plugin_dir in self.plugin_dirs:
            # Look for Python files
            for file_path in plugin_dir.glob("*.py"):
                if file_path.name.startswith("_"):
                    continue  # Skip private modules
                
                module_name = file_path.stem
                if module_name not in discovered:
                    discovered.append(module_name)
                    logger.debug(
                        "Discovered plugin module",
                        module=module_name,
                        path=str(file_path),
                    )
            
            # Look for Python packages (directories with __init__.py)
            for dir_path in plugin_dir.iterdir():
                if dir_path.is_dir() and (dir_path / "__init__.py").exists():
                    module_name = dir_path.name
                    if module_name not in discovered:
                        discovered.append(module_name)
                        logger.debug(
                            "Discovered plugin package",
                            module=module_name,
                            path=str(dir_path),
                        )
        
        return discovered
    
    def load_module(self, module_name: str) -> Any:
        """
        Load a Python module by name.
        
        Args:
            module_name: Name of the module to load
            
        Returns:
            Loaded module object
            
        Raises:
            PluginError: If module cannot be loaded
        """
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]
        
        try:
            # Try to import as a regular module first
            module = importlib.import_module(module_name)
            self._loaded_modules[module_name] = module
            logger.info("Loaded plugin module", module=module_name)
            return module
            
        except ImportError:
            # Try to load from plugin directories
            for plugin_dir in self.plugin_dirs:
                module_path = plugin_dir / f"{module_name}.py"
                if module_path.exists():
                    return self._load_module_from_file(module_name, module_path)
                
                package_path = plugin_dir / module_name / "__init__.py"
                if package_path.exists():
                    return self._load_module_from_file(
                        module_name,
                        package_path,
                        is_package=True,
                    )
            
            raise PluginError(f"Could not find plugin module: {module_name}")
    
    def _load_module_from_file(
        self,
        module_name: str,
        file_path: Path,
        is_package: bool = False,
    ) -> Any:
        """
        Load a module from a specific file path.
        
        Args:
            module_name: Name to give the module
            file_path: Path to the module file
            is_package: Whether this is a package __init__.py
            
        Returns:
            Loaded module object
            
        Raises:
            PluginError: If module cannot be loaded
        """
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None or spec.loader is None:
                raise PluginError(f"Could not load module spec for: {file_path}")
            
            module = importlib.util.module_from_spec(spec)
            
            # Add to sys.modules before executing
            sys.modules[module_name] = module
            
            # Add package path to sys.path if it's a package
            if is_package:
                package_dir = file_path.parent
                if str(package_dir) not in sys.path:
                    sys.path.insert(0, str(package_dir))
            
            spec.loader.exec_module(module)
            self._loaded_modules[module_name] = module
            
            logger.info(
                "Loaded plugin module from file",
                module=module_name,
                path=str(file_path),
            )
            return module
            
        except Exception as e:
            logger.error(
                "Failed to load plugin module",
                module=module_name,
                path=str(file_path),
                error=str(e),
            )
            raise PluginError(f"Failed to load module {module_name}: {e}")
    
    def reload_module(self, module_name: str) -> Any:
        """
        Reload a previously loaded module (useful for development).
        
        Args:
            module_name: Name of the module to reload
            
        Returns:
            Reloaded module object
            
        Raises:
            PluginError: If module cannot be reloaded
        """
        if module_name not in self._loaded_modules:
            return self.load_module(module_name)
        
        try:
            module = self._loaded_modules[module_name]
            reloaded = importlib.reload(module)
            self._loaded_modules[module_name] = reloaded
            
            # Clear cached plugin classes from this module
            to_remove = [
                name for name in self._plugin_classes
                if self._plugin_classes[name].__module__ == module_name
            ]
            for name in to_remove:
                del self._plugin_classes[name]
            
            logger.info("Reloaded plugin module", module=module_name)
            return reloaded
            
        except Exception as e:
            logger.error(
                "Failed to reload plugin module",
                module=module_name,
                error=str(e),
            )
            raise PluginError(f"Failed to reload module {module_name}: {e}")
    
    def find_plugin_classes(self, module: Any) -> Dict[str, Type[Plugin]]:
        """
        Find all Plugin subclasses in a module.
        
        Args:
            module: Module to search for plugin classes
            
        Returns:
            Dictionary of plugin name to plugin class
        """
        plugin_classes = {}
        
        for name, obj in inspect.getmembers(module):
            if (
                inspect.isclass(obj)
                and issubclass(obj, Plugin)
                and obj is not Plugin
                and not inspect.isabstract(obj)
            ):
                plugin_classes[name] = obj
                logger.debug(
                    "Found plugin class",
                    class_name=name,
                    module=module.__name__,
                )
        
        return plugin_classes
    
    def load_plugin_class(self, plugin_name: str) -> Type[Plugin]:
        """
        Load a specific plugin class.
        
        Args:
            plugin_name: Name of the plugin class (can be module.ClassName)
            
        Returns:
            Plugin class
            
        Raises:
            PluginError: If plugin class cannot be found
        """
        if plugin_name in self._plugin_classes:
            return self._plugin_classes[plugin_name]
        
        # Check if it's a fully qualified name
        if "." in plugin_name:
            module_name, class_name = plugin_name.rsplit(".", 1)
            module = self.load_module(module_name)
            
            if hasattr(module, class_name):
                plugin_class = getattr(module, class_name)
                if inspect.isclass(plugin_class) and issubclass(plugin_class, Plugin):
                    self._plugin_classes[plugin_name] = plugin_class
                    return plugin_class
            
            raise PluginError(f"Plugin class not found: {plugin_name}")
        
        # Search all loaded modules
        for module_name, module in self._loaded_modules.items():
            plugin_classes = self.find_plugin_classes(module)
            if plugin_name in plugin_classes:
                self._plugin_classes[plugin_name] = plugin_classes[plugin_name]
                return plugin_classes[plugin_name]
        
        # Try to discover and load new modules
        discovered = self.discover_plugins()
        for module_name in discovered:
            if module_name not in self._loaded_modules:
                try:
                    module = self.load_module(module_name)
                    plugin_classes = self.find_plugin_classes(module)
                    if plugin_name in plugin_classes:
                        self._plugin_classes[plugin_name] = plugin_classes[plugin_name]
                        return plugin_classes[plugin_name]
                except Exception:
                    continue
        
        raise PluginError(f"Plugin class not found: {plugin_name}")
    
    def instantiate_plugin(
        self,
        plugin_name: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Plugin:
        """
        Instantiate a plugin by name.
        
        Args:
            plugin_name: Name of the plugin to instantiate
            config: Configuration to pass to the plugin
            
        Returns:
            Plugin instance
            
        Raises:
            PluginError: If plugin cannot be instantiated
        """
        try:
            plugin_class = self.load_plugin_class(plugin_name)
            plugin = plugin_class(config=config)
            
            logger.info(
                "Instantiated plugin",
                plugin=plugin_name,
                metadata=plugin.metadata.to_dict(),
            )
            
            return plugin
            
        except Exception as e:
            logger.error(
                "Failed to instantiate plugin",
                plugin=plugin_name,
                error=str(e),
            )
            raise PluginError(f"Failed to instantiate plugin {plugin_name}: {e}")
    
    def validate_plugin(self, plugin: Plugin) -> bool:
        """
        Validate that a plugin conforms to the expected interface.
        
        Args:
            plugin: Plugin instance to validate
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            PluginValidationError: If plugin is invalid
        """
        # Check that it's a Plugin instance
        if not isinstance(plugin, Plugin):
            raise PluginValidationError(f"Object is not a Plugin instance: {type(plugin)}")
        
        # Check metadata
        try:
            metadata = plugin.metadata
            if not metadata.name:
                raise PluginValidationError("Plugin metadata missing name")
            if not metadata.version:
                raise PluginValidationError("Plugin metadata missing version")
        except Exception as e:
            raise PluginValidationError(f"Invalid plugin metadata: {e}")
        
        # Check that required methods exist
        required_methods = [
            "initialize",
            "shutdown",
            "pre_receive",
            "post_receive",
            "pre_upload",
            "post_upload",
        ]
        
        for method_name in required_methods:
            if not hasattr(plugin, method_name):
                raise PluginValidationError(f"Plugin missing required method: {method_name}")
            
            method = getattr(plugin, method_name)
            if not callable(method):
                raise PluginValidationError(f"Plugin method is not callable: {method_name}")
        
        return True
    
    def check_dependencies(self, plugin: Plugin) -> bool:
        """
        Check if plugin dependencies are satisfied.
        
        Args:
            plugin: Plugin to check dependencies for
            
        Returns:
            True if all dependencies are satisfied
            
        Raises:
            PluginDependencyError: If dependencies are not met
        """
        metadata = plugin.metadata
        
        for dependency in metadata.dependencies:
            # Check if dependency is a Python module
            try:
                importlib.import_module(dependency)
            except ImportError:
                # Check if it's another plugin
                try:
                    self.load_plugin_class(dependency)
                except PluginError:
                    raise PluginDependencyError(
                        f"Plugin dependency not found: {dependency}"
                    )
        
        return True