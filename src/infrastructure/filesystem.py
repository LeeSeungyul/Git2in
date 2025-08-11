import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from src.core.config import settings
from src.core.exceptions import ConflictError, NotFoundError, ValidationError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class FilesystemManager:
    """Manages filesystem operations for Git repositories"""

    def __init__(self, base_path: Optional[Path] = None):
        self.base_path = base_path or settings.repository_base_path
        self._ensure_base_directories()

    def _ensure_base_directories(self) -> None:
        """Ensure base directory structure exists"""
        self.base_path.mkdir(parents=True, exist_ok=True, mode=0o755)

        # Create namespaces directory
        namespaces_dir = self.base_path / "namespaces"
        namespaces_dir.mkdir(exist_ok=True, mode=0o755)

        logger.info(
            "filesystem_initialized",
            base_path=str(self.base_path),
            namespaces_path=str(namespaces_dir),
        )

    def validate_path_component(self, component: str) -> None:
        """Validate a single path component for security"""
        # Check for directory traversal attempts
        if ".." in component or "/" in component or "\\" in component:
            raise ValidationError(f"Invalid path component: {component}")

        # Check for null bytes
        if "\x00" in component:
            raise ValidationError("Path component contains null byte")

        # Check for special characters that could cause issues
        if component.startswith(".") and component not in [".git"]:
            raise ValidationError("Path component cannot start with dot")

    def get_namespace_path(self, namespace_name: str) -> Path:
        """Get the filesystem path for a namespace"""
        self.validate_path_component(namespace_name)
        return self.base_path / "namespaces" / namespace_name

    def get_repository_path(self, namespace_name: str, repo_name: str) -> Path:
        """Get the filesystem path for a repository"""
        self.validate_path_component(namespace_name)
        self.validate_path_component(repo_name)

        # Ensure repo name ends with .git
        if not repo_name.endswith(".git"):
            repo_name = f"{repo_name}.git"

        return self.get_namespace_path(namespace_name) / "repos" / repo_name

    def create_namespace_directory(self, namespace_name: str) -> Path:
        """Create a namespace directory structure"""
        namespace_path = self.get_namespace_path(namespace_name)

        if namespace_path.exists():
            raise ConflictError(f"Namespace directory already exists: {namespace_name}")

        try:
            # Create namespace directory
            namespace_path.mkdir(parents=True, mode=0o755)

            # Create repos subdirectory
            repos_dir = namespace_path / "repos"
            repos_dir.mkdir(mode=0o755)

            logger.info(
                "namespace_directory_created",
                namespace=namespace_name,
                path=str(namespace_path),
            )

            return namespace_path

        except Exception as e:
            # Clean up on failure
            if namespace_path.exists():
                shutil.rmtree(namespace_path, ignore_errors=True)

            logger.error(
                "namespace_directory_creation_failed",
                namespace=namespace_name,
                error=str(e),
            )
            raise

    def delete_namespace_directory(
        self, namespace_name: str, force: bool = False
    ) -> None:
        """Delete a namespace directory"""
        namespace_path = self.get_namespace_path(namespace_name)

        if not namespace_path.exists():
            raise NotFoundError(f"Namespace directory not found: {namespace_name}")

        # Check if namespace has repositories
        repos_dir = namespace_path / "repos"
        if repos_dir.exists() and any(repos_dir.iterdir()) and not force:
            raise ConflictError(f"Namespace contains repositories: {namespace_name}")

        try:
            shutil.rmtree(namespace_path)
            logger.info(
                "namespace_directory_deleted",
                namespace=namespace_name,
                path=str(namespace_path),
            )
        except Exception as e:
            logger.error(
                "namespace_directory_deletion_failed",
                namespace=namespace_name,
                error=str(e),
            )
            raise

    def list_namespace_repositories(self, namespace_name: str) -> List[str]:
        """List all repositories in a namespace"""
        namespace_path = self.get_namespace_path(namespace_name)
        repos_dir = namespace_path / "repos"

        if not repos_dir.exists():
            return []

        repositories = []
        for item in repos_dir.iterdir():
            if item.is_dir() and item.name.endswith(".git"):
                # Remove .git suffix for display
                repo_name = item.name[:-4]
                repositories.append(repo_name)

        return sorted(repositories)

    def calculate_directory_size(self, path: Path) -> int:
        """Calculate total size of a directory in bytes"""
        total_size = 0

        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    try:
                        total_size += filepath.stat().st_size
                    except (OSError, IOError):
                        # Skip files we can't access
                        pass
        except Exception as e:
            logger.warning(
                "directory_size_calculation_failed", path=str(path), error=str(e)
            )

        return total_size

    def calculate_repository_size(self, namespace_name: str, repo_name: str) -> int:
        """Calculate the size of a repository in bytes"""
        repo_path = self.get_repository_path(namespace_name, repo_name)

        if not repo_path.exists():
            return 0

        return self.calculate_directory_size(repo_path)

    def cleanup_orphaned_directories(self) -> List[str]:
        """Clean up empty namespace directories"""
        cleaned = []
        namespaces_dir = self.base_path / "namespaces"

        if not namespaces_dir.exists():
            return cleaned

        for namespace_dir in namespaces_dir.iterdir():
            if not namespace_dir.is_dir():
                continue

            repos_dir = namespace_dir / "repos"

            # Check if repos directory is empty or doesn't exist
            if not repos_dir.exists() or not any(repos_dir.iterdir()):
                try:
                    shutil.rmtree(namespace_dir)
                    cleaned.append(namespace_dir.name)
                    logger.info(
                        "orphaned_namespace_cleaned", namespace=namespace_dir.name
                    )
                except Exception as e:
                    logger.warning(
                        "orphaned_namespace_cleanup_failed",
                        namespace=namespace_dir.name,
                        error=str(e),
                    )

        return cleaned

    def verify_repository_structure(self, namespace_name: str, repo_name: str) -> bool:
        """Verify that a repository has valid bare git structure"""
        repo_path = self.get_repository_path(namespace_name, repo_name)

        if not repo_path.exists():
            return False

        # Check for essential bare repository components
        required_items = ["HEAD", "config", "objects", "refs"]

        for item in required_items:
            if not (repo_path / item).exists():
                return False

        # Check if HEAD file is readable
        try:
            head_file = repo_path / "HEAD"
            head_content = head_file.read_text().strip()

            # Valid HEAD should reference a branch or be a commit hash
            if not (
                head_content.startswith("ref: refs/")
                or re.match(r"^[0-9a-f]{40}$", head_content)
            ):
                return False
        except Exception:
            return False

        return True

    def get_namespace_stats(self, namespace_name: str) -> dict:
        """Get statistics for a namespace"""
        namespace_path = self.get_namespace_path(namespace_name)

        if not namespace_path.exists():
            raise NotFoundError(f"Namespace not found: {namespace_name}")

        repos = self.list_namespace_repositories(namespace_name)
        total_size = self.calculate_directory_size(namespace_path)

        return {
            "namespace": namespace_name,
            "repository_count": len(repos),
            "repositories": repos,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }
