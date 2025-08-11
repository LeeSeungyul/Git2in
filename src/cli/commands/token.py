"""Token management commands."""

import json
from datetime import datetime, timedelta
from typing import List, Optional

import questionary
import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from src.cli.utils.api_client import APIError
from src.cli.utils.context import CLIContext

app = typer.Typer(help="Manage API tokens")
console = Console()


# Available token scopes
AVAILABLE_SCOPES = {
    "read:namespace": "Read namespace information",
    "write:namespace": "Create and modify namespaces",
    "delete:namespace": "Delete namespaces",
    "read:repository": "Read repository information",
    "write:repository": "Create and modify repositories",
    "delete:repository": "Delete repositories",
    "read:user": "Read user information",
    "write:user": "Create and modify users",
    "delete:user": "Delete users",
    "read:token": "Read token information",
    "write:token": "Create and modify tokens",
    "delete:token": "Delete tokens",
    "admin": "Full administrative access",
}


def select_scopes_interactive() -> List[str]:
    """Interactive scope selection using questionary."""
    choices = [
        questionary.Choice(title=f"{scope} - {description}", value=scope)
        for scope, description in AVAILABLE_SCOPES.items()
    ]

    selected = questionary.checkbox(
        "Select token scopes (use space to select, enter to confirm):",
        choices=choices,
    ).ask()

    if not selected:
        console.print(
            "[yellow]No scopes selected. Using default read-only scopes.[/yellow]"
        )
        return ["read:namespace", "read:repository", "read:user"]

    return selected


@app.command("create")
def create_token(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Token name/description"),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", help="Interactive scope selection"
    ),
    scope: Optional[List[str]] = typer.Option(
        None, "--scope", "-s", help="Token scopes (can be used multiple times)"
    ),
    expires_in: Optional[int] = typer.Option(
        None, "--expires-in", help="Token expiration in days"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save token to file"
    ),
):
    """
    Create a new API token.

    Example:
        git2in token create "CI/CD Token" --interactive
        git2in token create "Read-only Token" --scope read:namespace --scope read:repository
        git2in token create "Temp Token" --expires-in 30 --output token.txt
    """
    cli_ctx: CLIContext = ctx.obj

    # Determine scopes
    if interactive and not scope:
        scopes = select_scopes_interactive()
    elif scope:
        scopes = list(scope)
    else:
        # Default scopes
        scopes = ["read:namespace", "read:repository", "read:user"]
        console.print(f"[dim]Using default scopes: {', '.join(scopes)}[/dim]")

    # Prepare token data
    token_data = {
        "name": name,
        "scopes": scopes,
    }

    if expires_in:
        expiry_date = datetime.utcnow() + timedelta(days=expires_in)
        token_data["expires_at"] = expiry_date.isoformat()

    try:
        with cli_ctx.get_api_client() as client:
            result = client.create_token(token_data)

            # Display token information
            cli_ctx.formatter.print_success(f"Token '{name}' created successfully")

            console.print(
                "\n[bold yellow]⚠ IMPORTANT: Save this token now. You won't be able to see it again![/bold yellow]\n"
            )

            # Display token
            token_value = result.get("token", result.get("access_token"))
            if token_value:
                console.print(f"[green]Token:[/green] {token_value}\n")

                # Save to file if requested
                if output_file:
                    try:
                        with open(output_file, "w") as f:
                            f.write(token_value)
                        console.print(
                            f"[green]✓[/green] Token saved to '{output_file}'"
                        )
                    except Exception as e:
                        console.print(f"[red]Failed to save token to file: {e}[/red]")

                # Offer to copy to clipboard
                try:
                    import pyperclip

                    if Confirm.ask("Copy token to clipboard?"):
                        pyperclip.copy(token_value)
                        console.print("[green]✓[/green] Token copied to clipboard")
                except ImportError:
                    pass  # pyperclip not available

            # Display token details
            console.print("\n[bold]Token Details:[/bold]")
            console.print(f"  ID: {result.get('id', 'N/A')}")
            console.print(f"  Name: {name}")
            console.print(f"  Scopes: {', '.join(scopes)}")
            if expires_in:
                console.print(f"  Expires: {result.get('expires_at', 'N/A')}")

            # Show example usage
            console.print("\n[bold]Example Usage:[/bold]")
            console.print(f"  git2in config set auth_token {token_value[:8]}...")
            console.print(
                f"  curl -H 'Authorization: Bearer {token_value[:8]}...' {cli_ctx.config.get('api_endpoint')}/api/v1/namespaces"
            )

    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to create token: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("list")
def list_tokens(
    ctx: typer.Context,
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum number of results"),
    offset: int = typer.Option(0, "--offset", help="Number of results to skip"),
    no_headers: bool = typer.Option(False, "--no-headers", help="Hide table headers"),
):
    """
    List your API tokens.

    Example:
        git2in token list
        git2in token list --limit 10
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        with cli_ctx.get_api_client() as client:
            tokens = client.list_tokens(limit=limit, offset=offset)

            # Format token data for display
            for token in tokens:
                # Format scopes
                scopes = token.get("scopes", [])
                token["scopes_display"] = ", ".join(scopes[:3])
                if len(scopes) > 3:
                    token["scopes_display"] += f" (+{len(scopes)-3})"

                # Format last used
                last_used = token.get("last_used")
                if last_used:
                    token["last_used_display"] = last_used
                else:
                    token["last_used_display"] = "Never"

                # Format expiry
                expires_at = token.get("expires_at")
                if expires_at:
                    token["expires_display"] = expires_at
                else:
                    token["expires_display"] = "Never"

            # Define columns to display
            columns = [
                "id",
                "name",
                "scopes_display",
                "last_used_display",
                "expires_display",
                "created_at",
            ]

            # Custom column names
            if not no_headers:
                # Create custom table for better column names
                table = Table(title="API Tokens")
                table.add_column("ID")
                table.add_column("Name")
                table.add_column("Scopes")
                table.add_column("Last Used")
                table.add_column("Expires")
                table.add_column("Created")

                for token in tokens:
                    table.add_row(
                        str(token.get("id", "")),
                        token.get("name", ""),
                        token.get("scopes_display", ""),
                        token.get("last_used_display", ""),
                        token.get("expires_display", ""),
                        token.get("created_at", ""),
                    )

                console.print(table)
            else:
                cli_ctx.formatter.print_list(
                    tokens,
                    columns=columns,
                    no_headers=no_headers,
                )

    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to list tokens: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("revoke")
def revoke_token(
    ctx: typer.Context,
    token_id: str = typer.Argument(..., help="Token ID to revoke"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """
    Revoke an API token.

    Example:
        git2in token revoke abc123
        git2in token revoke abc123 --force
    """
    cli_ctx: CLIContext = ctx.obj

    # Confirmation prompt unless --force is used
    if not force:
        if not Confirm.ask(f"Are you sure you want to revoke token '{token_id}'?"):
            cli_ctx.formatter.print_warning("Operation cancelled")
            raise typer.Exit(0)

    try:
        with cli_ctx.get_api_client() as client:
            client.revoke_token(token_id)
            cli_ctx.formatter.print_success(f"Token '{token_id}' revoked successfully")

    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Token '{token_id}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to revoke token: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("validate")
def validate_token(
    ctx: typer.Context,
    token: Optional[str] = typer.Option(
        None,
        "--token",
        "-t",
        help="Token to validate (uses configured token if not specified)",
    ),
):
    """
    Validate an API token.

    Example:
        git2in token validate
        git2in token validate --token <token>
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        # Use provided token or configured token
        if token:
            # Create temporary client with provided token
            api_endpoint = cli_ctx.config.get("api_endpoint")
            if not api_endpoint:
                cli_ctx.formatter.print_error("API endpoint not configured")
                raise typer.Exit(1)

            from src.cli.utils.api_client import APIClient

            client = APIClient(
                base_url=api_endpoint, auth_token=token, debug=cli_ctx.debug
            )
        else:
            client = cli_ctx.get_api_client()

        with client:
            result = client.validate_token()

            console.print("[green]✓[/green] Token is valid\n")

            # Display token information
            console.print("[bold]Token Information:[/bold]")
            console.print(f"  User: {result.get('user', 'N/A')}")
            console.print(f"  Name: {result.get('name', 'N/A')}")

            scopes = result.get("scopes", [])
            if scopes:
                console.print(f"  Scopes: {', '.join(scopes)}")
            else:
                console.print("  Scopes: None")

            expires_at = result.get("expires_at")
            if expires_at:
                console.print(f"  Expires: {expires_at}")
            else:
                console.print("  Expires: Never")

            # Check if token is expiring soon
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    days_left = (expiry - datetime.utcnow()).days

                    if days_left < 7:
                        console.print(
                            f"\n[yellow]⚠ Warning: Token expires in {days_left} days![/yellow]"
                        )
                    elif days_left < 30:
                        console.print(
                            f"\n[dim]Note: Token expires in {days_left} days[/dim]"
                        )
                except:
                    pass

    except APIError as e:
        if e.status_code == 401:
            cli_ctx.formatter.print_error("Token is invalid or expired")
        else:
            cli_ctx.formatter.print_error(f"Failed to validate token: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("rotate")
def rotate_token(
    ctx: typer.Context,
    token_id: str = typer.Argument(..., help="Token ID to rotate"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="New token name"),
    keep_scopes: bool = typer.Option(
        True, "--keep-scopes/--new-scopes", help="Keep existing scopes"
    ),
    expires_in: Optional[int] = typer.Option(
        None, "--expires-in", help="New token expiration in days"
    ),
):
    """
    Rotate an API token (revoke old, create new).

    Example:
        git2in token rotate abc123
        git2in token rotate abc123 --name "Rotated Token" --expires-in 90
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        with cli_ctx.get_api_client() as client:
            # Get existing token information
            console.print(f"[dim]Fetching token information...[/dim]")

            # Note: This assumes an endpoint to get token details exists
            # If not, we'll need to list tokens and find the matching one
            tokens = client.list_tokens()
            old_token = next((t for t in tokens if str(t.get("id")) == token_id), None)

            if not old_token:
                cli_ctx.formatter.print_error(f"Token '{token_id}' not found")
                raise typer.Exit(1)

            # Prepare new token data
            new_name = name or f"{old_token.get('name', 'Token')} (Rotated)"

            if keep_scopes:
                scopes = old_token.get(
                    "scopes", ["read:namespace", "read:repository", "read:user"]
                )
            else:
                console.print("\n[bold]Select new scopes:[/bold]")
                scopes = select_scopes_interactive()

            token_data = {
                "name": new_name,
                "scopes": scopes,
            }

            if expires_in:
                expiry_date = datetime.utcnow() + timedelta(days=expires_in)
                token_data["expires_at"] = expiry_date.isoformat()

            # Create new token
            console.print(f"\n[dim]Creating new token...[/dim]")
            new_token_result = client.create_token(token_data)

            # Revoke old token
            console.print(f"[dim]Revoking old token...[/dim]")
            client.revoke_token(token_id)

            # Display results
            cli_ctx.formatter.print_success("Token rotated successfully")

            console.print(
                "\n[bold yellow]⚠ IMPORTANT: Save this new token now![/bold yellow]\n"
            )

            token_value = new_token_result.get(
                "token", new_token_result.get("access_token")
            )
            if token_value:
                console.print(f"[green]New Token:[/green] {token_value}\n")

                # Offer to update configuration
                if Confirm.ask("Update CLI configuration with new token?"):
                    cli_ctx.config.set("auth_token", token_value)
                    cli_ctx.config.save()
                    console.print("[green]✓[/green] Configuration updated")

                # Offer to copy to clipboard
                try:
                    import pyperclip

                    if Confirm.ask("Copy new token to clipboard?"):
                        pyperclip.copy(token_value)
                        console.print("[green]✓[/green] Token copied to clipboard")
                except ImportError:
                    pass

            console.print(f"\n[green]✓[/green] Old token '{token_id}' has been revoked")
            console.print(
                f"[green]✓[/green] New token '{new_token_result.get('id')}' has been created"
            )

    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to rotate token: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)
