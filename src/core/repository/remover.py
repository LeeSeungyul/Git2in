"""Repository removal only"""
import shutil
from pathlib import Path

from .repository_types import RepositoryError, RepositoryNotFoundError


class RepositoryRemover:
    """Handles repository removal only"""
    
    def remove_repository(self, path: Path) -> None:
        """
        Remove a repository from disk
        
        Args:
            path: Path to repository
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryError: If removal fails
        """
        if not path.exists():
            raise RepositoryNotFoundError(str(path))
        
        try:
            # Remove entire repository directory
            shutil.rmtree(path)
        except PermissionError as e:
            raise RepositoryError(f"Permission denied removing repository: {e}")
        except Exception as e:
            raise RepositoryError(f"Failed to remove repository: {e}")
    
    def archive_repository(self, path: Path, archive_path: Path) -> None:
        """
        Archive a repository before removal
        
        Args:
            path: Repository path
            archive_path: Where to store archive
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
            RepositoryError: If archiving fails
        """
        if not path.exists():
            raise RepositoryNotFoundError(str(path))
        
        try:
            # Create archive directory
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create tar.gz archive
            import tarfile
            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(path, arcname=path.name)
                
        except Exception as e:
            raise RepositoryError(f"Failed to archive repository: {e}")