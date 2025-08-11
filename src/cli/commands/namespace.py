"""Namespace management commands."""

from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm

from src.cli.utils.api_client import APIError
from src.cli.utils.context import CLIContext

app = typer.Typer(help="Manage namespaces")
console = Console()


@app.command("create")
def create_namespace(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Namespace name"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="Namespace description"
    ),
    public: bool = typer.Option(False, "--public", help="Make namespace public"),
):
    """
    Create a new namespace.

    Example:
        git2in namespace create my-namespace --description "My namespace" --public
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        with cli_ctx.get_api_client() as client:
            data = {
                "name": name,
                "description": description,
                "is_public": public,
            }

            result = client.create_namespace(data)
            cli_ctx.formatter.print_success(f"Namespace '{name}' created successfully")

            if cli_ctx.debug:
                cli_ctx.formatter.print_detail(result, title="Namespace Details")

    except APIError as e:
        if e.status_code == 409:
            cli_ctx.formatter.print_error(f"Namespace '{name}' already exists")
        else:
            cli_ctx.formatter.print_error(f"Failed to create namespace: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("list")
def list_namespaces(
    ctx: typer.Context,
    filter: Optional[str] = typer.Option(
        None, "--filter", "-f", help="Filter namespaces by name"
    ),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum number of results"),
    offset: int = typer.Option(0, "--offset", help="Number of results to skip"),
    no_headers: bool = typer.Option(False, "--no-headers", help="Hide table headers"),
):
    """
    List all namespaces.

    Example:
        git2in namespace list
        git2in namespace list --filter "dev-" --limit 20
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        with cli_ctx.get_api_client() as client:
            namespaces = client.list_namespaces(limit=limit, offset=offset)

            # Apply client-side filtering if specified
            if filter:
                namespaces = [ns for ns in namespaces if filter in ns.get("name", "")]

            # Define columns to display
            columns = ["name", "description", "is_public", "created_at"]

            cli_ctx.formatter.print_list(
                namespaces,
                columns=columns,
                title="Namespaces",
                no_headers=no_headers,
            )

    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to list namespaces: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("show")
def show_namespace(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Namespace name"),
):
    """
    Show detailed information about a namespace.

    Example:
        git2in namespace show my-namespace
    """
    cli_ctx: CLIContext = ctx.obj

    try:
        with cli_ctx.get_api_client() as client:
            namespace = client.get_namespace(name)
            cli_ctx.formatter.print_detail(namespace, title=f"Namespace: {name}")

    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Namespace '{name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to get namespace: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("delete")
def delete_namespace(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Namespace name"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """
    Delete a namespace.

    Example:
        git2in namespace delete my-namespace
        git2in namespace delete my-namespace --force
    """
    cli_ctx: CLIContext = ctx.obj

    # Confirmation prompt unless --force is used
    if not force:
        if not Confirm.ask(f"Are you sure you want to delete namespace '{name}'?"):
            cli_ctx.formatter.print_warning("Operation cancelled")
            raise typer.Exit(0)

    try:
        with cli_ctx.get_api_client() as client:
            client.delete_namespace(name)
            cli_ctx.formatter.print_success(f"Namespace '{name}' deleted successfully")

    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Namespace '{name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to delete namespace: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("update")
def update_namespace(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Namespace name"),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="New description"
    ),
    public: Optional[bool] = typer.Option(
        None, "--public/--private", help="Set visibility"
    ),
):
    """
    Update namespace settings.

    Example:
        git2in namespace update my-namespace --description "Updated description"
        git2in namespace update my-namespace --private
    """
    cli_ctx: CLIContext = ctx.obj

    # Build update data
    update_data = {}
    if description is not None:
        update_data["description"] = description
    if public is not None:
        update_data["is_public"] = public

    if not update_data:
        cli_ctx.formatter.print_warning("No updates specified")
        raise typer.Exit(0)

    try:
        with cli_ctx.get_api_client() as client:
            # Note: This assumes a PATCH endpoint exists
            result = client.patch(f"/api/v1/namespaces/{name}", json_data=update_data)
            cli_ctx.formatter.print_success(f"Namespace '{name}' updated successfully")

            if cli_ctx.debug:
                cli_ctx.formatter.print_detail(result, title="Updated Namespace")

    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Namespace '{name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to update namespace: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)
