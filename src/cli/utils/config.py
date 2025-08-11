"""Configuration management for Git2in CLI."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import toml
import yaml
from rich.console import Console

console = Console()


class ConfigManager:
    """Manage CLI configuration."""

    def __init__(self, config_file: Optional[Path] = None):
        """
        Initialize configuration manager.

        Args:
            config_file: Optional path to configuration file
        """
        self.config_path = config_file or self._get_default_config_path()
        self.config: Dict[str, Any] = {}
        self._load_config()
        self._apply_env_overrides()

    def _get_default_config_path(self) -> Path:
        """Get default configuration file path."""
        config_dir = Path.home() / ".git2in"
        config_dir.mkdir(exist_ok=True, parents=True)
        return config_dir / "config.yml"

    def _load_config(self):
        """Load configuration from file."""
        if not self.config_path.exists():
            # Create default configuration
            self.config = {
                "api_endpoint": "http://localhost:8000",
                "output_format": "table",
                "default_namespace": None,
                "auth_token": None,
            }
            self.save()
            return

        # Determine file format and load
        suffix = self.config_path.suffix.lower()

        try:
            with open(self.config_path, "r") as f:
                if suffix in [".yml", ".yaml"]:
                    self.config = yaml.safe_load(f) or {}
                elif suffix == ".toml":
                    self.config = toml.load(f)
                else:
                    # Default to YAML
                    self.config = yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to load config: {e}[/yellow]")
            self.config = {}

    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        env_mapping = {
            "GIT2IN_API_ENDPOINT": "api_endpoint",
            "GIT2IN_TOKEN": "auth_token",
            "GIT2IN_OUTPUT_FORMAT": "output_format",
            "GIT2IN_DEFAULT_NAMESPACE": "default_namespace",
        }

        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value:
                self.config[config_key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        """
        Set configuration value.

        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self.config.copy()

    def save(self):
        """Save configuration to file."""
        try:
            suffix = self.config_path.suffix.lower()

            with open(self.config_path, "w") as f:
                if suffix in [".yml", ".yaml"]:
                    yaml.safe_dump(self.config, f, default_flow_style=False)
                elif suffix == ".toml":
                    toml.dump(self.config, f)
                else:
                    # Default to YAML
                    yaml.safe_dump(self.config, f, default_flow_style=False)

            # Set appropriate permissions (readable/writable by owner only)
            self.config_path.chmod(0o600)

        except Exception as e:
            console.print(f"[red]Error saving config: {e}[/red]")
            raise
