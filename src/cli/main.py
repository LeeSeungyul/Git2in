"""Git2in Management CLI Tool."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from src.cli import __version__
from src.cli.commands import namespace, repository, token, user
from src.cli.utils.config import ConfigManager
from src.cli.utils.context import CLIContext
from src.cli.utils.output import OutputFormatter

app = typer.Typer(
    name="git2in",
    help="Git2in Management CLI - A command-line interface for Git2in administration",
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    pretty_exceptions_enable=False,
)

console = Console()


def version_callback(value: bool):
    """Display version and exit."""
    if value:
        console.print(f"Git2in CLI v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Enable debug output",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output format: table, json, yaml",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
    ),
):
    """
    Git2in Management CLI

    A comprehensive command-line interface for Git2in administration and operations.
    """
    # Initialize CLI context
    config_manager = ConfigManager(config_file)
    formatter = OutputFormatter(output_format or config_manager.get("output_format", "table"))
    
    cli_context = CLIContext(
        debug=debug,
        config=config_manager,
        formatter=formatter,
        console=console,
    )
    
    ctx.obj = cli_context
    
    if debug:
        console.print("[dim]Debug mode enabled[/dim]")


# Add command groups
app.add_typer(namespace.app, name="namespace", help="Manage namespaces")
app.add_typer(repository.app, name="repo", help="Manage repositories")
app.add_typer(token.app, name="token", help="Manage API tokens")
app.add_typer(user.app, name="user", help="Manage users")


@app.command("config")
def config_command(
    ctx: typer.Context,
    action: str = typer.Argument(..., help="Action: get, set, list"),
    key: Optional[str] = typer.Argument(None, help="Configuration key"),
    value: Optional[str] = typer.Argument(None, help="Configuration value"),
):
    """
    Manage configuration settings.
    
    Examples:
        git2in config list
        git2in config get api_endpoint
        git2in config set api_endpoint http://localhost:8000
    """
    cli_ctx: CLIContext = ctx.obj
    config = cli_ctx.config
    
    if action == "list":
        table = Table(title="Configuration Settings")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in config.get_all().items():
            if key != "auth_token":  # Hide sensitive values
                table.add_row(key, str(value))
            else:
                table.add_row(key, "***" if value else "Not set")
        
        console.print(table)
    
    elif action == "get":
        if not key:
            console.print("[red]Error: Key is required for get action[/red]")
            raise typer.Exit(1)
        
        value = config.get(key)
        if value is not None:
            if key == "auth_token":
                console.print("***" if value else "Not set")
            else:
                console.print(value)
        else:
            console.print(f"[yellow]Configuration key '{key}' not found[/yellow]")
    
    elif action == "set":
        if not key or value is None:
            console.print("[red]Error: Both key and value are required for set action[/red]")
            raise typer.Exit(1)
        
        config.set(key, value)
        config.save()
        console.print(f"[green]✓[/green] Configuration updated: {key} = {'***' if key == 'auth_token' else value}")
    
    else:
        console.print(f"[red]Error: Unknown action '{action}'. Use: get, set, or list[/red]")
        raise typer.Exit(1)


@app.command("doctor")
def doctor_command(ctx: typer.Context):
    """
    Diagnose Git2in CLI configuration and connectivity.
    """
    cli_ctx: CLIContext = ctx.obj
    console.print("[bold]Git2in CLI Doctor[/bold]\n")
    
    # Check configuration
    console.print("📋 Configuration:")
    config_path = cli_ctx.config.config_path
    if config_path.exists():
        console.print(f"  [green]✓[/green] Configuration file found: {config_path}")
    else:
        console.print(f"  [yellow]⚠[/yellow] Configuration file not found: {config_path}")
    
    # Check API endpoint
    api_endpoint = cli_ctx.config.get("api_endpoint")
    if api_endpoint:
        console.print(f"  [green]✓[/green] API endpoint configured: {api_endpoint}")
        
        # Try to connect to API
        try:
            import httpx
            response = httpx.get(f"{api_endpoint}/health", timeout=5.0)
            if response.status_code == 200:
                console.print(f"  [green]✓[/green] API is reachable")
            else:
                console.print(f"  [red]✗[/red] API returned status {response.status_code}")
        except Exception as e:
            console.print(f"  [red]✗[/red] Failed to connect to API: {e}")
    else:
        console.print("  [yellow]⚠[/yellow] API endpoint not configured")
    
    # Check authentication
    auth_token = cli_ctx.config.get("auth_token")
    if auth_token:
        console.print("  [green]✓[/green] Authentication token configured")
    else:
        console.print("  [yellow]⚠[/yellow] Authentication token not configured")
    
    # Check shell completion
    console.print("\n📝 Shell Completion:")
    console.print("  To install shell completion, run:")
    console.print("    [cyan]git2in --install-completion[/cyan]")
    
    console.print("\n[bold]Summary:[/bold]")
    if api_endpoint and auth_token:
        console.print("  [green]✓[/green] CLI is properly configured")
    else:
        console.print("  [yellow]⚠[/yellow] Some configuration is missing. Run:")
        if not api_endpoint:
            console.print("    [cyan]git2in config set api_endpoint <url>[/cyan]")
        if not auth_token:
            console.print("    [cyan]git2in config set auth_token <token>[/cyan]")


@app.command("completion")
def completion_command(
    install: bool = typer.Option(False, "--install", help="Install shell completion"),
    shell: Optional[str] = typer.Option(None, help="Shell type: bash, zsh, fish"),
):
    """
    Generate or install shell completion scripts.
    """
    if install:
        typer.echo("Installing shell completion...")
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "typer", "src.cli.main", "utils", "generate-completion", "install"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]✓[/green] Shell completion installed successfully")
            console.print("Please restart your shell or run: [cyan]source ~/.bashrc[/cyan]")
        else:
            console.print(f"[red]Error installing completion:[/red] {result.stderr}")
    else:
        # Show completion script
        if not shell:
            shell = "bash"
        
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "typer", "src.cli.main", "utils", "generate-completion", shell],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print(result.stdout)
        else:
            console.print(f"[red]Error generating completion:[/red] {result.stderr}")


if __name__ == "__main__":
    app()