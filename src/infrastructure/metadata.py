import fcntl
import json
import os
import tempfile
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.core.exceptions import InternalServerError, NotFoundError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class RepositoryMetadata(BaseModel):
    """Schema for repository metadata"""

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    created_at: datetime
    updated_at: datetime
    owner_id: str
    owner_username: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    is_private: bool = True
    is_archived: bool = False
    default_branch: str = "main"

    # Statistics
    commit_count: int = 0
    branch_count: int = 0
    tag_count: int = 0
    contributor_count: int = 0
    size_bytes: int = 0

    # Custom properties
    custom_properties: Dict[str, Any] = Field(default_factory=dict)

    # Metadata versioning
    schema_version: int = 1


class MetadataManager:
    """Manages JSON-based metadata storage for repositories"""

    METADATA_FILENAME = "git2in-metadata.json"
    CACHE_SIZE = 100  # Number of metadata entries to cache

    def __init__(self):
        self._cache_enabled = True

    @lru_cache(maxsize=CACHE_SIZE)
    def _get_cached_metadata(self, metadata_path: str) -> Optional[RepositoryMetadata]:
        """Get cached metadata (cache key is the file path)"""
        if not self._cache_enabled:
            return None

        try:
            path = Path(metadata_path)
            if not path.exists():
                return None

            with open(path, "r") as f:
                data = json.load(f)
                return RepositoryMetadata(**data)
        except Exception:
            return None

    def clear_cache(self) -> None:
        """Clear the metadata cache"""
        self._get_cached_metadata.cache_clear()
        logger.debug("metadata_cache_cleared")

    def disable_cache(self) -> None:
        """Disable caching (useful for tests)"""
        self._cache_enabled = False
        self.clear_cache()

    def enable_cache(self) -> None:
        """Enable caching"""
        self._cache_enabled = True

    def get_metadata_path(self, repo_path: Path) -> Path:
        """Get the path to the metadata file for a repository"""
        return repo_path / self.METADATA_FILENAME

    def read_metadata(self, repo_path: Path) -> Optional[RepositoryMetadata]:
        """Read metadata from a repository"""
        metadata_path = self.get_metadata_path(repo_path)

        # Try to get from cache first
        if self._cache_enabled:
            cached = self._get_cached_metadata(str(metadata_path))
            if cached:
                return cached

        if not metadata_path.exists():
            return None

        try:
            with open(metadata_path, "r") as f:
                # Use file locking for read
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                    metadata = RepositoryMetadata(**data)

                    # Update cache
                    if self._cache_enabled:
                        self._get_cached_metadata.cache_clear()
                        self._get_cached_metadata(str(metadata_path))

                    return metadata
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        except json.JSONDecodeError as e:
            logger.error(
                "metadata_read_json_error", path=str(metadata_path), error=str(e)
            )
            raise InternalServerError(f"Invalid metadata JSON: {str(e)}")

        except Exception as e:
            logger.error("metadata_read_failed", path=str(metadata_path), error=str(e))
            raise InternalServerError(f"Failed to read metadata: {str(e)}")

    def write_metadata(
        self, repo_path: Path, metadata: RepositoryMetadata, atomic: bool = True
    ) -> None:
        """Write metadata to a repository (atomic by default)"""
        metadata_path = self.get_metadata_path(repo_path)

        # Update timestamp
        metadata.updated_at = datetime.utcnow()

        try:
            if atomic:
                # Write to temporary file first
                temp_fd, temp_path = tempfile.mkstemp(
                    dir=repo_path, prefix=".metadata-", suffix=".tmp"
                )

                try:
                    with os.fdopen(temp_fd, "w") as f:
                        # Use file locking
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        try:
                            json.dump(
                                metadata.model_dump(mode="json"),
                                f,
                                indent=2,
                                sort_keys=True,
                            )
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                    # Atomic rename
                    os.replace(temp_path, metadata_path)

                except Exception:
                    # Clean up temp file on error
                    if Path(temp_path).exists():
                        os.unlink(temp_path)
                    raise
            else:
                # Non-atomic write (faster but less safe)
                with open(metadata_path, "w") as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    try:
                        json.dump(
                            metadata.model_dump(mode="json"),
                            f,
                            indent=2,
                            sort_keys=True,
                        )
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Invalidate cache for this path
            if self._cache_enabled:
                self._get_cached_metadata.cache_clear()

            logger.debug("metadata_written", path=str(metadata_path), atomic=atomic)

        except Exception as e:
            logger.error("metadata_write_failed", path=str(metadata_path), error=str(e))
            raise InternalServerError(f"Failed to write metadata: {str(e)}")

    def delete_metadata(self, repo_path: Path) -> None:
        """Delete metadata for a repository"""
        metadata_path = self.get_metadata_path(repo_path)

        if metadata_path.exists():
            try:
                os.unlink(metadata_path)

                # Invalidate cache
                if self._cache_enabled:
                    self._get_cached_metadata.cache_clear()

                logger.debug("metadata_deleted", path=str(metadata_path))

            except Exception as e:
                logger.error(
                    "metadata_deletion_failed", path=str(metadata_path), error=str(e)
                )
                raise InternalServerError(f"Failed to delete metadata: {str(e)}")

    def create_initial_metadata(
        self,
        owner_id: str,
        owner_username: Optional[str] = None,
        description: Optional[str] = None,
        is_private: bool = True,
        default_branch: str = "main",
        **kwargs,
    ) -> RepositoryMetadata:
        """Create initial metadata for a new repository"""
        now = datetime.utcnow()

        return RepositoryMetadata(
            created_at=now,
            updated_at=now,
            owner_id=owner_id,
            owner_username=owner_username,
            description=description,
            is_private=is_private,
            default_branch=default_branch,
            **kwargs,
        )

    def update_statistics(
        self,
        repo_path: Path,
        commit_count: Optional[int] = None,
        branch_count: Optional[int] = None,
        tag_count: Optional[int] = None,
        contributor_count: Optional[int] = None,
        size_bytes: Optional[int] = None,
    ) -> None:
        """Update repository statistics in metadata"""
        metadata = self.read_metadata(repo_path)

        if metadata is None:
            raise NotFoundError(f"Metadata not found for repository: {repo_path}")

        if commit_count is not None:
            metadata.commit_count = commit_count
        if branch_count is not None:
            metadata.branch_count = branch_count
        if tag_count is not None:
            metadata.tag_count = tag_count
        if contributor_count is not None:
            metadata.contributor_count = contributor_count
        if size_bytes is not None:
            metadata.size_bytes = size_bytes

        self.write_metadata(repo_path, metadata)

    def add_custom_property(self, repo_path: Path, key: str, value: Any) -> None:
        """Add or update a custom property in metadata"""
        metadata = self.read_metadata(repo_path)

        if metadata is None:
            raise NotFoundError(f"Metadata not found for repository: {repo_path}")

        metadata.custom_properties[key] = value
        self.write_metadata(repo_path, metadata)

    def remove_custom_property(self, repo_path: Path, key: str) -> None:
        """Remove a custom property from metadata"""
        metadata = self.read_metadata(repo_path)

        if metadata is None:
            raise NotFoundError(f"Metadata not found for repository: {repo_path}")

        if key in metadata.custom_properties:
            del metadata.custom_properties[key]
            self.write_metadata(repo_path, metadata)

    def backup_metadata(self, repo_path: Path, backup_suffix: str = ".backup") -> Path:
        """Create a backup of the metadata file"""
        metadata_path = self.get_metadata_path(repo_path)

        if not metadata_path.exists():
            raise NotFoundError(f"Metadata file not found: {metadata_path}")

        backup_path = metadata_path.with_suffix(metadata_path.suffix + backup_suffix)

        try:
            import shutil

            shutil.copy2(metadata_path, backup_path)

            logger.info(
                "metadata_backed_up",
                original=str(metadata_path),
                backup=str(backup_path),
            )

            return backup_path

        except Exception as e:
            logger.error(
                "metadata_backup_failed", path=str(metadata_path), error=str(e)
            )
            raise InternalServerError(f"Failed to backup metadata: {str(e)}")

    def restore_metadata(self, repo_path: Path, backup_suffix: str = ".backup") -> None:
        """Restore metadata from a backup"""
        metadata_path = self.get_metadata_path(repo_path)
        backup_path = metadata_path.with_suffix(metadata_path.suffix + backup_suffix)

        if not backup_path.exists():
            raise NotFoundError(f"Backup file not found: {backup_path}")

        try:
            import shutil

            shutil.copy2(backup_path, metadata_path)

            # Invalidate cache
            if self._cache_enabled:
                self._get_cached_metadata.cache_clear()

            logger.info(
                "metadata_restored", backup=str(backup_path), target=str(metadata_path)
            )

        except Exception as e:
            logger.error(
                "metadata_restore_failed", backup=str(backup_path), error=str(e)
            )
            raise InternalServerError(f"Failed to restore metadata: {str(e)}")
