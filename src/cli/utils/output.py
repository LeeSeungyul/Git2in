"""Output formatting utilities for CLI."""

import json
from enum import Enum
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console
from rich.table import Table


class OutputFormat(Enum):
    """Output format options."""

    TABLE = "table"
    JSON = "json"
    YAML = "yaml"


class OutputFormatter:
    """Handle output formatting for different formats."""

    def __init__(self, format_type: str = "table"):
        """
        Initialize output formatter.

        Args:
            format_type: Output format (table, json, yaml)
        """
        self.console = Console()
        try:
            self.format = OutputFormat(format_type.lower())
        except ValueError:
            self.format = OutputFormat.TABLE

    def print_list(
        self,
        items: List[Dict[str, Any]],
        columns: Optional[List[str]] = None,
        title: Optional[str] = None,
        no_headers: bool = False,
    ):
        """
        Print a list of items.

        Args:
            items: List of items to print
            columns: Column names to display (for table format)
            title: Table title (for table format)
            no_headers: Whether to hide headers (for table format)
        """
        if not items:
            self.console.print("[dim]No items found[/dim]")
            return

        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps(items, indent=2, default=str))

        elif self.format == OutputFormat.YAML:
            self.console.print(
                yaml.safe_dump(items, default_flow_style=False, default_str=str)
            )

        else:  # TABLE
            # Determine columns from first item if not specified
            if not columns and items:
                columns = list(items[0].keys())

            table = Table(title=title, show_header=not no_headers)

            # Add columns
            for col in columns or []:
                # Format column names
                col_name = col.replace("_", " ").title()
                table.add_column(col_name)

            # Add rows
            for item in items:
                row = []
                for col in columns or []:
                    value = item.get(col, "")
                    # Format special values
                    if value is None:
                        value = "[dim]-[/dim]"
                    elif isinstance(value, bool):
                        value = "[green]✓[/green]" if value else "[red]✗[/red]"
                    elif col == "auth_token" and value:
                        value = "***"
                    else:
                        value = str(value)
                    row.append(value)
                table.add_row(*row)

            self.console.print(table)

    def print_detail(
        self,
        item: Dict[str, Any],
        title: Optional[str] = None,
    ):
        """
        Print detailed view of a single item.

        Args:
            item: Item to print
            title: Optional title
        """
        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps(item, indent=2, default=str))

        elif self.format == OutputFormat.YAML:
            self.console.print(
                yaml.safe_dump(item, default_flow_style=False, default_str=str)
            )

        else:  # TABLE
            if title:
                self.console.print(f"[bold]{title}[/bold]\n")

            for key, value in item.items():
                # Format key
                formatted_key = key.replace("_", " ").title()

                # Format value
                if value is None:
                    formatted_value = "[dim]Not set[/dim]"
                elif isinstance(value, bool):
                    formatted_value = "[green]Yes[/green]" if value else "[red]No[/red]"
                elif key == "auth_token" and value:
                    formatted_value = "***"
                elif isinstance(value, (list, dict)):
                    formatted_value = json.dumps(value, indent=2)
                else:
                    formatted_value = str(value)

                self.console.print(f"[cyan]{formatted_key}:[/cyan] {formatted_value}")

    def print_success(self, message: str):
        """Print success message."""
        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps({"status": "success", "message": message}))
        elif self.format == OutputFormat.YAML:
            self.console.print(
                yaml.safe_dump({"status": "success", "message": message})
            )
        else:
            self.console.print(f"[green]✓[/green] {message}")

    def print_error(self, message: str):
        """Print error message."""
        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps({"status": "error", "message": message}))
        elif self.format == OutputFormat.YAML:
            self.console.print(yaml.safe_dump({"status": "error", "message": message}))
        else:
            self.console.print(f"[red]✗[/red] {message}")

    def print_warning(self, message: str):
        """Print warning message."""
        if self.format == OutputFormat.JSON:
            self.console.print(json.dumps({"status": "warning", "message": message}))
        elif self.format == OutputFormat.YAML:
            self.console.print(
                yaml.safe_dump({"status": "warning", "message": message})
            )
        else:
            self.console.print(f"[yellow]⚠[/yellow] {message}")
