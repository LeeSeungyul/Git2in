"""User management commands."""

from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from src.cli.utils.api_client import APIError
from src.cli.utils.context import CLIContext

app = typer.Typer(help="Manage users")
console = Console()


@app.command("create")
def create_user(
    ctx: typer.Context,
    username: str = typer.Argument(..., help="Username"),
    email: str = typer.Option(..., "--email", "-e", help="User email address"),
    full_name: Optional[str] = typer.Option(None, "--full-name", "-n", help="Full name"),
    role: Optional[str] = typer.Option("user", "--role", "-r", help="User role (admin, user)"),
    active: bool = typer.Option(True, "--active/--inactive", help="Account status"),
):
    """
    Create a new user.
    
    Example:
        git2in user create johndoe --email john@example.com --full-name "John Doe"
        git2in user create admin --email admin@example.com --role admin
    """
    cli_ctx: CLIContext = ctx.obj
    
    try:
        with cli_ctx.get_api_client() as client:
            data = {
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role,
                "is_active": active,
            }
            
            result = client.create_user(data)
            cli_ctx.formatter.print_success(f"User '{username}' created successfully")
            
            if cli_ctx.debug:
                cli_ctx.formatter.print_detail(result, title="User Details")
    
    except APIError as e:
        if e.status_code == 409:
            cli_ctx.formatter.print_error(f"User '{username}' or email '{email}' already exists")
        else:
            cli_ctx.formatter.print_error(f"Failed to create user: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("list")
def list_users(
    ctx: typer.Context,
    role: Optional[str] = typer.Option(None, "--role", "-r", help="Filter by role"),
    active: Optional[bool] = typer.Option(None, "--active/--inactive", help="Filter by status"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search users"),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum number of results"),
    offset: int = typer.Option(0, "--offset", help="Number of results to skip"),
    no_headers: bool = typer.Option(False, "--no-headers", help="Hide table headers"),
):
    """
    List users.
    
    Example:
        git2in user list
        git2in user list --role admin
        git2in user list --search "john" --active
    """
    cli_ctx: CLIContext = ctx.obj
    
    try:
        with cli_ctx.get_api_client() as client:
            users = client.list_users(limit=limit, offset=offset)
            
            # Apply client-side filtering
            if role:
                users = [u for u in users if u.get("role") == role]
            if active is not None:
                users = [u for u in users if u.get("is_active") == active]
            if search:
                search_lower = search.lower()
                users = [
                    u for u in users
                    if search_lower in u.get("username", "").lower()
                    or search_lower in u.get("email", "").lower()
                    or search_lower in u.get("full_name", "").lower()
                ]
            
            # Define columns to display
            columns = ["username", "email", "full_name", "role", "is_active", "created_at"]
            
            cli_ctx.formatter.print_list(
                users,
                columns=columns,
                title="Users",
                no_headers=no_headers,
            )
    
    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to list users: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("show")
def show_user(
    ctx: typer.Context,
    username: str = typer.Argument(..., help="Username or user ID"),
):
    """
    Show detailed information about a user.
    
    Example:
        git2in user show johndoe
    """
    cli_ctx: CLIContext = ctx.obj
    
    try:
        with cli_ctx.get_api_client() as client:
            user = client.get_user(username)
            cli_ctx.formatter.print_detail(user, title=f"User: {username}")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"User '{username}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to get user: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("update")
def update_user(
    ctx: typer.Context,
    username: str = typer.Argument(..., help="Username or user ID"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="New email address"),
    full_name: Optional[str] = typer.Option(None, "--full-name", "-n", help="New full name"),
    role: Optional[str] = typer.Option(None, "--role", "-r", help="New role"),
    active: Optional[bool] = typer.Option(None, "--active/--inactive", help="Account status"),
):
    """
    Update user information.
    
    Example:
        git2in user update johndoe --email newemail@example.com
        git2in user update johndoe --role admin
        git2in user update johndoe --inactive
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Build update data
    update_data = {}
    if email is not None:
        update_data["email"] = email
    if full_name is not None:
        update_data["full_name"] = full_name
    if role is not None:
        update_data["role"] = role
    if active is not None:
        update_data["is_active"] = active
    
    if not update_data:
        cli_ctx.formatter.print_warning("No updates specified")
        raise typer.Exit(0)
    
    try:
        with cli_ctx.get_api_client() as client:
            result = client.update_user(username, update_data)
            cli_ctx.formatter.print_success(f"User '{username}' updated successfully")
            
            if cli_ctx.debug:
                cli_ctx.formatter.print_detail(result, title="Updated User")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"User '{username}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to update user: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("delete")
def delete_user(
    ctx: typer.Context,
    username: str = typer.Argument(..., help="Username or user ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
    cascade: bool = typer.Option(False, "--cascade", help="Delete all user's data"),
):
    """
    Delete a user.
    
    Example:
        git2in user delete johndoe
        git2in user delete johndoe --force --cascade
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Confirmation prompt unless --force is used
    if not force:
        if cascade:
            console.print("[bold red]Warning:[/bold red] This will delete the user and ALL associated data!")
        if not Confirm.ask(f"Are you sure you want to delete user '{username}'?"):
            cli_ctx.formatter.print_warning("Operation cancelled")
            raise typer.Exit(0)
    
    try:
        with cli_ctx.get_api_client() as client:
            # Add cascade parameter if specified
            params = {"cascade": cascade} if cascade else {}
            client.delete(f"/api/v1/users/{username}", params=params)
            cli_ctx.formatter.print_success(f"User '{username}' deleted successfully")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"User '{username}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to delete user: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("reset-password")
def reset_password(
    ctx: typer.Context,
    username: str = typer.Argument(..., help="Username or user ID"),
    generate: bool = typer.Option(True, "--generate/--prompt", help="Generate or prompt for password"),
):
    """
    Reset user password.
    
    Example:
        git2in user reset-password johndoe
        git2in user reset-password johndoe --prompt
    """
    cli_ctx: CLIContext = ctx.obj
    
    try:
        with cli_ctx.get_api_client() as client:
            if generate:
                # Request password reset with generated password
                result = client.post(f"/api/v1/users/{username}/reset-password", json_data={})
                
                if "password" in result:
                    console.print(f"[green]✓[/green] Password reset successfully")
                    console.print(f"\n[yellow]New password:[/yellow] {result['password']}")
                    console.print("\n[dim]Please save this password securely and share it with the user.[/dim]")
                else:
                    cli_ctx.formatter.print_success(f"Password reset for user '{username}'")
            else:
                # Prompt for new password
                password = Prompt.ask("Enter new password", password=True)
                confirm = Prompt.ask("Confirm password", password=True)
                
                if password != confirm:
                    cli_ctx.formatter.print_error("Passwords do not match")
                    raise typer.Exit(1)
                
                client.post(
                    f"/api/v1/users/{username}/reset-password",
                    json_data={"password": password}
                )
                cli_ctx.formatter.print_success(f"Password reset for user '{username}'")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"User '{username}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to reset password: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)