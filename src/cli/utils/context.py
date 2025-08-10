"""CLI context management."""

from dataclasses import dataclass
from typing import Optional

from rich.console import Console

from src.cli.utils.config import ConfigManager
from src.cli.utils.output import OutputFormatter


@dataclass
class CLIContext:
    """Context object passed through CLI commands."""
    
    debug: bool
    config: ConfigManager
    formatter: OutputFormatter
    console: Console
    
    def get_api_client(self):
        """
        Get configured API client.
        
        Returns:
            APIClient instance
        """
        from src.cli.utils.api_client import APIClient
        
        api_endpoint = self.config.get("api_endpoint")
        auth_token = self.config.get("auth_token")
        
        if not api_endpoint:
            self.console.print("[red]Error: API endpoint not configured[/red]")
            self.console.print("Run: [cyan]git2in config set api_endpoint <url>[/cyan]")
            raise SystemExit(1)
        
        return APIClient(
            base_url=api_endpoint,
            auth_token=auth_token,
            debug=self.debug,
        )