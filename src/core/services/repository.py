import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from src.core.config import settings
from src.core.exceptions import (ConflictError, InternalServerError,
                                 NotFoundError, ValidationError)
from src.core.models import (AuditAction, AuditEntry, Namespace, Repository,
                             ResourceType)
from src.infrastructure.filesystem import FilesystemManager
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class GitCommandError(Exception):
    """Exception raised when a git command fails"""

    pass


class RepositoryService:
    """Service for managing Git repositories"""

    def __init__(self, filesystem_manager: Optional[FilesystemManager] = None):
        self.fs_manager = filesystem_manager or FilesystemManager()
        self.git_binary = settings.git_binary_path
        self._verify_git_installation()

    def _verify_git_installation(self) -> None:
        """Verify that git is installed and accessible"""
        try:
            result = subprocess.run(
                [self.git_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                raise InternalServerError("Git is not properly installed")

            logger.info("git_verified", version=result.stdout.strip())

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("git_verification_failed", error=str(e))
            raise InternalServerError("Git binary not found or not accessible")

    def _execute_git_command(
        self,
        args: List[str],
        cwd: Optional[Path] = None,
        timeout: int = 30,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute a git command safely"""
        cmd = [self.git_binary] + args

        logger.debug(
            "executing_git_command",
            command=" ".join(cmd),
            cwd=str(cwd) if cwd else None,
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=timeout,
                check=False,
            )

            if check and result.returncode != 0:
                raise GitCommandError(
                    f"Git command failed: {result.stderr or result.stdout}"
                )

            return result

        except subprocess.TimeoutExpired:
            logger.error("git_command_timeout", command=" ".join(cmd))
            raise InternalServerError("Git command timed out")

        except Exception as e:
            logger.error("git_command_error", command=" ".join(cmd), error=str(e))
            raise InternalServerError(f"Git command failed: {str(e)}")

    def create_repository(
        self,
        namespace: Namespace,
        repository: Repository,
        user_id: Optional[UUID] = None,
    ) -> Repository:
        """Create a new bare Git repository"""
        repo_path = self.fs_manager.get_repository_path(
            namespace.name, repository.git_dir_name
        )

        # Check if repository already exists
        if repo_path.exists():
            raise ConflictError(f"Repository already exists: {repository.full_name}")

        # Ensure namespace directory exists
        namespace_path = self.fs_manager.get_namespace_path(namespace.name)
        if not namespace_path.exists():
            self.fs_manager.create_namespace_directory(namespace.name)

        try:
            # Create repository directory
            repo_path.mkdir(parents=True, mode=0o750)

            # Initialize bare repository
            self._execute_git_command(
                ["init", "--bare", "--initial-branch", repository.default_branch],
                cwd=repo_path,
            )

            # Set repository description
            if repository.description:
                description_file = repo_path / "description"
                description_file.write_text(repository.description)

            # Update repository size
            repository.size_bytes = self.fs_manager.calculate_repository_size(
                namespace.name, repository.name
            )

            # Create audit entry
            audit = AuditEntry.create_success(
                action=AuditAction.CREATE,
                resource_type=ResourceType.REPOSITORY,
                resource_id=repository.full_name,
                resource_name=repository.name,
                user_id=user_id,
                details={
                    "namespace": namespace.name,
                    "default_branch": repository.default_branch,
                    "is_private": repository.is_private,
                },
            )
            audit.log_to_structured()

            logger.info(
                "repository_created",
                repository=repository.full_name,
                path=str(repo_path),
            )

            return repository

        except Exception as e:
            # Clean up on failure
            if repo_path.exists():
                shutil.rmtree(repo_path, ignore_errors=True)

            # Create failure audit entry
            audit = AuditEntry.create_failure(
                action=AuditAction.CREATE,
                resource_type=ResourceType.REPOSITORY,
                resource_id=repository.full_name,
                error_message=str(e),
                user_id=user_id,
            )
            audit.log_to_structured()

            logger.error(
                "repository_creation_failed",
                repository=repository.full_name,
                error=str(e),
            )
            raise

    def delete_repository(
        self, namespace_name: str, repo_name: str, user_id: Optional[UUID] = None
    ) -> None:
        """Delete a repository"""
        repo_path = self.fs_manager.get_repository_path(
            namespace_name, f"{repo_name}.git"
        )

        if not repo_path.exists():
            raise NotFoundError(f"Repository not found: {namespace_name}/{repo_name}")

        try:
            # Remove the repository directory
            shutil.rmtree(repo_path)

            # Create audit entry
            audit = AuditEntry.create_success(
                action=AuditAction.DELETE,
                resource_type=ResourceType.REPOSITORY,
                resource_id=f"{namespace_name}/{repo_name}",
                user_id=user_id,
            )
            audit.log_to_structured()

            logger.info(
                "repository_deleted",
                repository=f"{namespace_name}/{repo_name}",
                path=str(repo_path),
            )

        except Exception as e:
            # Create failure audit entry
            audit = AuditEntry.create_failure(
                action=AuditAction.DELETE,
                resource_type=ResourceType.REPOSITORY,
                resource_id=f"{namespace_name}/{repo_name}",
                error_message=str(e),
                user_id=user_id,
            )
            audit.log_to_structured()

            logger.error(
                "repository_deletion_failed",
                repository=f"{namespace_name}/{repo_name}",
                error=str(e),
            )
            raise InternalServerError(f"Failed to delete repository: {str(e)}")

    def list_repositories(self, namespace_name: str) -> List[str]:
        """List all repositories in a namespace"""
        return self.fs_manager.list_namespace_repositories(namespace_name)

    def get_repository_info(
        self, namespace_name: str, repo_name: str
    ) -> Dict[str, Any]:
        """Get detailed information about a repository"""
        repo_path = self.fs_manager.get_repository_path(
            namespace_name, f"{repo_name}.git"
        )

        if not repo_path.exists():
            raise NotFoundError(f"Repository not found: {namespace_name}/{repo_name}")

        # Verify repository structure
        if not self.fs_manager.verify_repository_structure(namespace_name, repo_name):
            raise InternalServerError(
                f"Invalid repository structure: {namespace_name}/{repo_name}"
            )

        info = {
            "name": repo_name,
            "namespace": namespace_name,
            "full_name": f"{namespace_name}/{repo_name}",
            "path": str(repo_path),
            "size_bytes": self.fs_manager.calculate_repository_size(
                namespace_name, repo_name
            ),
        }

        # Get default branch
        try:
            head_file = repo_path / "HEAD"
            head_content = head_file.read_text().strip()

            if head_content.startswith("ref: refs/heads/"):
                info["default_branch"] = head_content.replace("ref: refs/heads/", "")
            else:
                info["default_branch"] = "main"
        except Exception:
            info["default_branch"] = "main"

        # Get description
        try:
            description_file = repo_path / "description"
            if description_file.exists():
                description = description_file.read_text().strip()
                if description and not description.startswith("Unnamed repository"):
                    info["description"] = description
        except Exception:
            pass

        # Get last modified time
        try:
            # Check objects directory for recent activity
            objects_dir = repo_path / "objects"
            if objects_dir.exists():
                latest_mtime = 0
                for item in objects_dir.rglob("*"):
                    if item.is_file():
                        mtime = item.stat().st_mtime
                        if mtime > latest_mtime:
                            latest_mtime = mtime

                if latest_mtime > 0:
                    info["last_modified"] = datetime.fromtimestamp(
                        latest_mtime
                    ).isoformat()
        except Exception:
            pass

        # Count branches
        try:
            refs_heads = repo_path / "refs" / "heads"
            if refs_heads.exists():
                branches = list(refs_heads.iterdir())
                info["branch_count"] = len(branches)
                info["branches"] = [b.name for b in branches if b.is_file()]
        except Exception:
            info["branch_count"] = 0
            info["branches"] = []

        # Count tags
        try:
            refs_tags = repo_path / "refs" / "tags"
            if refs_tags.exists():
                tags = list(refs_tags.iterdir())
                info["tag_count"] = len(tags)
                info["tags"] = [t.name for t in tags if t.is_file()]
        except Exception:
            info["tag_count"] = 0
            info["tags"] = []

        return info

    def update_repository_description(
        self,
        namespace_name: str,
        repo_name: str,
        description: str,
        user_id: Optional[UUID] = None,
    ) -> None:
        """Update repository description"""
        repo_path = self.fs_manager.get_repository_path(
            namespace_name, f"{repo_name}.git"
        )

        if not repo_path.exists():
            raise NotFoundError(f"Repository not found: {namespace_name}/{repo_name}")

        try:
            description_file = repo_path / "description"
            description_file.write_text(description)

            # Create audit entry
            audit = AuditEntry.create_success(
                action=AuditAction.UPDATE,
                resource_type=ResourceType.REPOSITORY,
                resource_id=f"{namespace_name}/{repo_name}",
                user_id=user_id,
                details={"field": "description"},
            )
            audit.log_to_structured()

            logger.info(
                "repository_description_updated",
                repository=f"{namespace_name}/{repo_name}",
            )

        except Exception as e:
            logger.error(
                "repository_description_update_failed",
                repository=f"{namespace_name}/{repo_name}",
                error=str(e),
            )
            raise InternalServerError(f"Failed to update description: {str(e)}")

    def verify_repository_health(
        self, namespace_name: str, repo_name: str
    ) -> Tuple[bool, Optional[str]]:
        """Verify repository health and integrity"""
        repo_path = self.fs_manager.get_repository_path(
            namespace_name, f"{repo_name}.git"
        )

        if not repo_path.exists():
            return False, "Repository does not exist"

        # Check basic structure
        if not self.fs_manager.verify_repository_structure(namespace_name, repo_name):
            return False, "Invalid repository structure"

        # Run git fsck to check integrity
        try:
            result = self._execute_git_command(
                ["fsck", "--no-progress"], cwd=repo_path, check=False
            )

            if result.returncode != 0:
                return False, f"Repository integrity check failed: {result.stderr}"

            return True, None

        except Exception as e:
            return False, f"Health check failed: {str(e)}"
