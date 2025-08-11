"""Plugin configuration management system."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import structlog
import yaml
from pydantic import BaseModel, Field, ValidationError

from src.plugins.base import PluginConfigurationError
from src.plugins.sandbox import ResourceLimits

logger = structlog.get_logger(__name__)


class PluginResourceConfig(BaseModel):
    """Resource limit configuration for a plugin."""

    cpu_time: Optional[int] = Field(
        None, ge=1, le=3600, description="CPU time limit in seconds"
    )
    memory: Optional[int] = Field(
        None, ge=1048576, le=2147483648, description="Memory limit in bytes"
    )
    file_size: Optional[int] = Field(
        None, ge=0, le=1073741824, description="Max file size in bytes"
    )
    file_descriptors: Optional[int] = Field(
        None, ge=10, le=1000, description="Max file descriptors"
    )
    processes: Optional[int] = Field(None, ge=1, le=100, description="Max processes")
    timeout: Optional[float] = Field(
        30.0, ge=1.0, le=300.0, description="Execution timeout in seconds"
    )

    def to_resource_limits(self) -> ResourceLimits:
        """Convert to ResourceLimits object."""
        return ResourceLimits(
            cpu_time=self.cpu_time,
            memory=self.memory,
            file_size=self.file_size,
            file_descriptors=self.file_descriptors,
            processes=self.processes,
            timeout=self.timeout,
        )


class PluginConfig(BaseModel):
    """Configuration for a single plugin."""

    name: str = Field(..., description="Plugin name")
    enabled: bool = Field(True, description="Whether plugin is enabled")
    module: Optional[str] = Field(None, description="Python module path")
    executable: Optional[str] = Field(None, description="External executable path")
    priority: str = Field("NORMAL", description="Execution priority")

    # Plugin-specific settings
    settings: Dict[str, Any] = Field(
        default_factory=dict, description="Plugin-specific settings"
    )

    # Resource limits
    resources: Optional[PluginResourceConfig] = Field(
        None, description="Resource limits"
    )

    # Sandboxing options
    sandbox: bool = Field(False, description="Whether to run in sandbox")
    network_enabled: bool = Field(False, description="Allow network access in sandbox")

    # Hook-specific configuration
    hooks: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Hook-specific configuration",
    )

    # Dependencies
    dependencies: List[str] = Field(
        default_factory=list, description="Plugin dependencies"
    )

    # Environment variables
    environment: Dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for plugin",
    )

    class Config:
        extra = "allow"  # Allow additional fields


class PluginConfigHierarchy(BaseModel):
    """Hierarchical plugin configuration (global -> namespace -> repository)."""

    global_config: Optional[PluginConfig] = None
    namespace_configs: Dict[str, PluginConfig] = Field(default_factory=dict)
    repository_configs: Dict[str, PluginConfig] = Field(default_factory=dict)

    def get_effective_config(
        self,
        namespace: Optional[str] = None,
        repository: Optional[str] = None,
    ) -> PluginConfig:
        """
        Get effective configuration with proper precedence.

        Args:
            namespace: Namespace name
            repository: Repository name (format: namespace/repo)

        Returns:
            Merged configuration with repository > namespace > global precedence
        """
        # Start with global config
        if self.global_config:
            config = self.global_config.dict()
        else:
            config = {}

        # Merge namespace config
        if namespace and namespace in self.namespace_configs:
            namespace_config = self.namespace_configs[namespace].dict()
            config = self._merge_configs(config, namespace_config)

        # Merge repository config
        if repository and repository in self.repository_configs:
            repo_config = self.repository_configs[repository].dict()
            config = self._merge_configs(config, repo_config)

        return PluginConfig(**config)

    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two configuration dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result


class PluginConfigManager:
    """Manages plugin configuration loading and validation."""

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration manager.

        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = config_dir or Path("/etc/git2in/plugins.d")
        self._configs: Dict[str, PluginConfigHierarchy] = {}
        self._loaded_files: Dict[str, float] = {}  # Track file modification times

    def load_config_file(self, file_path: Union[str, Path]) -> Dict[str, PluginConfig]:
        """
        Load plugin configuration from a file.

        Args:
            file_path: Path to configuration file (YAML or JSON)

        Returns:
            Dictionary of plugin name to configuration

        Raises:
            PluginConfigurationError: If configuration is invalid
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise PluginConfigurationError(f"Configuration file not found: {file_path}")

        try:
            # Determine file format
            if file_path.suffix in [".yml", ".yaml"]:
                with open(file_path, "r") as f:
                    data = yaml.safe_load(f)
            elif file_path.suffix == ".json":
                with open(file_path, "r") as f:
                    data = json.load(f)
            else:
                raise PluginConfigurationError(
                    f"Unsupported file format: {file_path.suffix}"
                )

            # Parse plugins section
            if "plugins" not in data:
                raise PluginConfigurationError(
                    "Missing 'plugins' section in configuration"
                )

            configs = {}
            for plugin_name, plugin_data in data["plugins"].items():
                try:
                    plugin_data["name"] = plugin_name
                    configs[plugin_name] = PluginConfig(**plugin_data)
                except ValidationError as e:
                    raise PluginConfigurationError(
                        f"Invalid configuration for plugin '{plugin_name}': {e}"
                    )

            # Track file modification time
            self._loaded_files[str(file_path)] = file_path.stat().st_mtime

            logger.info(
                "Loaded plugin configuration",
                file=str(file_path),
                plugins=list(configs.keys()),
            )

            return configs

        except Exception as e:
            raise PluginConfigurationError(
                f"Failed to load configuration from {file_path}: {e}"
            )

    def load_directory(
        self, directory: Optional[Path] = None
    ) -> Dict[str, PluginConfig]:
        """
        Load all configuration files from a directory.

        Args:
            directory: Directory to load from (uses self.config_dir if not provided)

        Returns:
            Merged configuration from all files
        """
        directory = directory or self.config_dir

        if not directory.exists():
            logger.warning(f"Configuration directory not found: {directory}")
            return {}

        all_configs = {}

        # Load all YAML and JSON files
        for file_path in sorted(directory.glob("*.{yml,yaml,json}")):
            try:
                configs = self.load_config_file(file_path)
                # Merge with existing configs (later files override earlier ones)
                all_configs.update(configs)
            except Exception as e:
                logger.error(f"Failed to load config file {file_path}: {e}")

        return all_configs

    def load_hierarchy(
        self,
        global_config_path: Optional[Path] = None,
        namespace_config_dir: Optional[Path] = None,
        repo_config_dir: Optional[Path] = None,
    ) -> Dict[str, PluginConfigHierarchy]:
        """
        Load hierarchical configuration.

        Args:
            global_config_path: Path to global configuration file
            namespace_config_dir: Directory with namespace-specific configs
            repo_config_dir: Directory with repository-specific configs

        Returns:
            Dictionary of plugin name to hierarchical configuration
        """
        hierarchies = {}

        # Load global configuration
        global_configs = {}
        if global_config_path and global_config_path.exists():
            global_configs = self.load_config_file(global_config_path)

        # Load namespace configurations
        namespace_configs = {}
        if namespace_config_dir and namespace_config_dir.exists():
            for ns_file in namespace_config_dir.glob("*.{yml,yaml,json}"):
                namespace = ns_file.stem
                ns_configs = self.load_config_file(ns_file)
                for plugin_name, config in ns_configs.items():
                    if plugin_name not in namespace_configs:
                        namespace_configs[plugin_name] = {}
                    namespace_configs[plugin_name][namespace] = config

        # Load repository configurations
        repo_configs = {}
        if repo_config_dir and repo_config_dir.exists():
            for repo_file in repo_config_dir.glob("*.{yml,yaml,json}"):
                repo = repo_file.stem.replace("__", "/")  # Convert __ to /
                r_configs = self.load_config_file(repo_file)
                for plugin_name, config in r_configs.items():
                    if plugin_name not in repo_configs:
                        repo_configs[plugin_name] = {}
                    repo_configs[plugin_name][repo] = config

        # Build hierarchies
        all_plugins = set(global_configs.keys())
        all_plugins.update(namespace_configs.keys())
        all_plugins.update(repo_configs.keys())

        for plugin_name in all_plugins:
            hierarchy = PluginConfigHierarchy(
                global_config=global_configs.get(plugin_name),
                namespace_configs=namespace_configs.get(plugin_name, {}),
                repository_configs=repo_configs.get(plugin_name, {}),
            )
            hierarchies[plugin_name] = hierarchy

        self._configs = hierarchies
        return hierarchies

    def get_plugin_config(
        self,
        plugin_name: str,
        namespace: Optional[str] = None,
        repository: Optional[str] = None,
    ) -> Optional[PluginConfig]:
        """
        Get effective configuration for a plugin.

        Args:
            plugin_name: Name of the plugin
            namespace: Optional namespace context
            repository: Optional repository context

        Returns:
            Plugin configuration or None if not found
        """
        if plugin_name not in self._configs:
            return None

        hierarchy = self._configs[plugin_name]
        return hierarchy.get_effective_config(namespace, repository)

    def reload_if_changed(self) -> bool:
        """
        Reload configuration files if they have been modified.

        Returns:
            True if any files were reloaded
        """
        reloaded = False

        for file_path, mtime in list(self._loaded_files.items()):
            path = Path(file_path)
            if path.exists():
                current_mtime = path.stat().st_mtime
                if current_mtime > mtime:
                    try:
                        self.load_config_file(path)
                        reloaded = True
                        logger.info(f"Reloaded modified config file: {file_path}")
                    except Exception as e:
                        logger.error(f"Failed to reload config file {file_path}: {e}")

        return reloaded

    def validate_all(self) -> List[str]:
        """
        Validate all loaded configurations.

        Returns:
            List of validation errors (empty if all valid)
        """
        errors = []

        for plugin_name, hierarchy in self._configs.items():
            # Check global config
            if hierarchy.global_config:
                try:
                    hierarchy.global_config.dict()
                except ValidationError as e:
                    errors.append(f"Global config for {plugin_name}: {e}")

            # Check namespace configs
            for ns, config in hierarchy.namespace_configs.items():
                try:
                    config.dict()
                except ValidationError as e:
                    errors.append(f"Namespace {ns} config for {plugin_name}: {e}")

            # Check repository configs
            for repo, config in hierarchy.repository_configs.items():
                try:
                    config.dict()
                except ValidationError as e:
                    errors.append(f"Repository {repo} config for {plugin_name}: {e}")

        return errors

    def export_schema(self, output_path: Path):
        """
        Export JSON schema for plugin configuration.

        Args:
            output_path: Path to write schema file
        """
        schema = PluginConfig.schema()

        with open(output_path, "w") as f:
            json.dump(schema, f, indent=2)

        logger.info(f"Exported configuration schema to {output_path}")
