"""Repository management commands."""

from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm

from src.cli.utils.api_client import APIError
from src.cli.utils.context import CLIContext

app = typer.Typer(help="Manage repositories")
console = Console()


@app.command("create")
def create_repository(
    ctx: typer.Context,
    full_name: str = typer.Argument(..., help="Repository full name (namespace/repo)"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Repository description"),
    private: bool = typer.Option(False, "--private", help="Make repository private"),
    init: bool = typer.Option(False, "--init", help="Initialize with README"),
):
    """
    Create a new repository.
    
    Example:
        git2in repo create myorg/myrepo --description "My repository"
        git2in repo create myorg/myrepo --private --init
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Parse namespace and repository name
    try:
        namespace, repo_name = full_name.split("/", 1)
    except ValueError:
        cli_ctx.formatter.print_error("Invalid repository name format. Use: namespace/repo")
        raise typer.Exit(1)
    
    try:
        with cli_ctx.get_api_client() as client:
            data = {
                "name": repo_name,
                "description": description,
                "is_private": private,
                "initialize": init,
            }
            
            result = client.create_repository(namespace, data)
            cli_ctx.formatter.print_success(f"Repository '{full_name}' created successfully")
            
            # Show clone URL if available
            if "clone_url" in result:
                console.print(f"\n[cyan]Clone URL:[/cyan] {result['clone_url']}")
            
            if cli_ctx.debug:
                cli_ctx.formatter.print_detail(result, title="Repository Details")
    
    except APIError as e:
        if e.status_code == 409:
            cli_ctx.formatter.print_error(f"Repository '{full_name}' already exists")
        elif e.status_code == 404:
            cli_ctx.formatter.print_error(f"Namespace '{namespace}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to create repository: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("list")
def list_repositories(
    ctx: typer.Context,
    namespace: Optional[str] = typer.Option(None, "--namespace", "-n", help="Filter by namespace"),
    filter: Optional[str] = typer.Option(None, "--filter", "-f", help="Filter repositories by name"),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum number of results"),
    offset: int = typer.Option(0, "--offset", help="Number of results to skip"),
    no_headers: bool = typer.Option(False, "--no-headers", help="Hide table headers"),
):
    """
    List repositories.
    
    Example:
        git2in repo list
        git2in repo list --namespace myorg
        git2in repo list --filter "test-" --limit 20
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Use default namespace if configured and not specified
    if not namespace:
        namespace = cli_ctx.config.get("default_namespace")
    
    try:
        with cli_ctx.get_api_client() as client:
            repositories = client.list_repositories(
                namespace=namespace,
                limit=limit,
                offset=offset
            )
            
            # Apply client-side filtering if specified
            if filter:
                repositories = [
                    repo for repo in repositories 
                    if filter in repo.get("name", "")
                ]
            
            # Format full names
            for repo in repositories:
                repo["full_name"] = f"{repo.get('namespace', '')}/{repo.get('name', '')}"
            
            # Define columns to display
            columns = ["full_name", "description", "is_private", "updated_at"]
            
            cli_ctx.formatter.print_list(
                repositories,
                columns=columns,
                title="Repositories",
                no_headers=no_headers,
            )
    
    except APIError as e:
        cli_ctx.formatter.print_error(f"Failed to list repositories: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("show")
def show_repository(
    ctx: typer.Context,
    full_name: str = typer.Argument(..., help="Repository full name (namespace/repo)"),
):
    """
    Show detailed information about a repository.
    
    Example:
        git2in repo show myorg/myrepo
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Parse namespace and repository name
    try:
        namespace, repo_name = full_name.split("/", 1)
    except ValueError:
        cli_ctx.formatter.print_error("Invalid repository name format. Use: namespace/repo")
        raise typer.Exit(1)
    
    try:
        with cli_ctx.get_api_client() as client:
            repository = client.get_repository(namespace, repo_name)
            cli_ctx.formatter.print_detail(repository, title=f"Repository: {full_name}")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Repository '{full_name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to get repository: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("delete")
def delete_repository(
    ctx: typer.Context,
    full_name: str = typer.Argument(..., help="Repository full name (namespace/repo)"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """
    Delete a repository.
    
    Example:
        git2in repo delete myorg/myrepo
        git2in repo delete myorg/myrepo --force
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Parse namespace and repository name
    try:
        namespace, repo_name = full_name.split("/", 1)
    except ValueError:
        cli_ctx.formatter.print_error("Invalid repository name format. Use: namespace/repo")
        raise typer.Exit(1)
    
    # Confirmation prompt unless --force is used
    if not force:
        console.print(f"[bold red]Warning:[/bold red] This will permanently delete the repository and all its data!")
        if not Confirm.ask(f"Are you sure you want to delete '{full_name}'?"):
            cli_ctx.formatter.print_warning("Operation cancelled")
            raise typer.Exit(0)
    
    try:
        with cli_ctx.get_api_client() as client:
            client.delete_repository(namespace, repo_name)
            cli_ctx.formatter.print_success(f"Repository '{full_name}' deleted successfully")
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Repository '{full_name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to delete repository: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)


@app.command("clone")
def clone_repository(
    ctx: typer.Context,
    full_name: str = typer.Argument(..., help="Repository full name (namespace/repo)"),
    directory: Optional[str] = typer.Option(None, "--dir", "-d", help="Target directory"),
):
    """
    Clone a repository using git.
    
    Example:
        git2in repo clone myorg/myrepo
        git2in repo clone myorg/myrepo --dir ./projects/myrepo
    """
    cli_ctx: CLIContext = ctx.obj
    
    # Parse namespace and repository name
    try:
        namespace, repo_name = full_name.split("/", 1)
    except ValueError:
        cli_ctx.formatter.print_error("Invalid repository name format. Use: namespace/repo")
        raise typer.Exit(1)
    
    try:
        with cli_ctx.get_api_client() as client:
            # Get repository to fetch clone URL
            repository = client.get_repository(namespace, repo_name)
            
            clone_url = repository.get("clone_url")
            if not clone_url:
                # Construct clone URL from API endpoint
                api_endpoint = cli_ctx.config.get("api_endpoint")
                clone_url = f"{api_endpoint}/git/{namespace}/{repo_name}.git"
            
            # Prepare git command
            import subprocess
            
            target_dir = directory or repo_name
            
            console.print(f"Cloning repository from: [cyan]{clone_url}[/cyan]")
            
            # Add authentication if token is available
            auth_token = cli_ctx.config.get("auth_token")
            if auth_token:
                # Inject token into URL for authentication
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(clone_url)
                auth_url = urlunparse((
                    parsed.scheme,
                    f"token:{auth_token}@{parsed.netloc}",
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
                clone_url = auth_url
            
            # Execute git clone
            result = subprocess.run(
                ["git", "clone", clone_url, target_dir],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                cli_ctx.formatter.print_success(f"Repository cloned to '{target_dir}'")
            else:
                cli_ctx.formatter.print_error(f"Git clone failed: {result.stderr}")
                raise typer.Exit(1)
    
    except APIError as e:
        if e.status_code == 404:
            cli_ctx.formatter.print_error(f"Repository '{full_name}' not found")
        else:
            cli_ctx.formatter.print_error(f"Failed to get repository: {e}")
        raise typer.Exit(1)
    except Exception as e:
        cli_ctx.formatter.print_error(f"Unexpected error: {e}")
        raise typer.Exit(1)