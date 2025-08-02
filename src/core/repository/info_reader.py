"""Repository information reading only"""
from pathlib import Path
from datetime import datetime
import os

from .repository_types import RepositoryInfo, RepositoryNotFoundError


class RepositoryInfoReader:
    """Handles reading repository information only"""
    
    def read_info(self, repo_path: Path) -> RepositoryInfo:
        """
        Read repository information
        
        Args:
            repo_path: Repository path
            
        Returns:
            Repository information
            
        Raises:
            RepositoryNotFoundError: If repository doesn't exist
        """
        if not repo_path.exists():
            raise RepositoryNotFoundError(str(repo_path))
        
        # Calculate repository size
        size_bytes = self._calculate_size(repo_path)
        
        # Count objects
        object_count = self._count_objects(repo_path)
        
        # Get default branch
        default_branch = self._get_default_branch(repo_path)
        
        # Get last modified time
        last_modified = self._get_last_modified(repo_path)
        
        # Check if bare
        is_bare = self._is_bare_repository(repo_path)
        
        return RepositoryInfo(
            path=repo_path,
            size_bytes=size_bytes,
            object_count=object_count,
            default_branch=default_branch,
            last_modified=last_modified,
            is_bare=is_bare
        )
    
    def _calculate_size(self, repo_path: Path) -> int:
        """Calculate total repository size"""
        total_size = 0
        
        for dirpath, dirnames, filenames in os.walk(repo_path):
            for filename in filenames:
                filepath = Path(dirpath) / filename
                try:
                    total_size += filepath.stat().st_size
                except OSError:
                    pass
        
        return total_size
    
    def _count_objects(self, repo_path: Path) -> int:
        """Count objects in repository"""
        count = 0
        objects_dir = repo_path / 'objects'
        
        if not objects_dir.exists():
            return 0
        
        # Count loose objects
        for item in objects_dir.iterdir():
            if item.is_dir() and len(item.name) == 2:  # Object directories are 2 chars
                for obj_file in item.iterdir():
                    if obj_file.is_file():
                        count += 1
        
        # Count packed objects (simplified)
        pack_dir = objects_dir / 'pack'
        if pack_dir.exists():
            for pack_file in pack_dir.glob('*.idx'):
                # Each .idx file represents multiple packed objects
                # This is a simplified count
                count += 100  # Estimate
        
        return count
    
    def _get_default_branch(self, repo_path: Path) -> str:
        """Get default branch name"""
        head_file = repo_path / 'HEAD'
        
        try:
            content = head_file.read_text().strip()
            if content.startswith('ref: refs/heads/'):
                return content[16:]
        except Exception:
            pass
        
        return 'main'
    
    def _get_last_modified(self, repo_path: Path) -> datetime:
        """Get last modification time"""
        latest_time = 0
        
        # Check objects directory for latest changes
        objects_dir = repo_path / 'objects'
        if objects_dir.exists():
            for dirpath, dirnames, filenames in os.walk(objects_dir):
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    try:
                        mtime = filepath.stat().st_mtime
                        latest_time = max(latest_time, mtime)
                    except OSError:
                        pass
        
        if latest_time == 0:
            # Fallback to repository directory modification time
            try:
                latest_time = repo_path.stat().st_mtime
            except OSError:
                latest_time = datetime.now().timestamp()
        
        return datetime.fromtimestamp(latest_time)
    
    def _is_bare_repository(self, repo_path: Path) -> bool:
        """Check if repository is bare"""
        config_file = repo_path / 'config'
        
        if config_file.exists():
            try:
                content = config_file.read_text()
                # Look for bare = true in config
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('bare') and '=' in line:
                        value = line.split('=', 1)[1].strip()
                        return value.lower() == 'true'
            except Exception:
                pass
        
        # Check for presence of working directory files
        # In a bare repo, there should be no working tree
        return not (repo_path / '.git').exists()