"""Directory operations management module."""
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import aiofiles.os
import tempfile


class DirectoryManager:
    """Handles directory operations only."""
    
    def __init__(self, base_path: Path):
        self.base_path = Path(base_path).resolve()
        self.temp_base = self.base_path / ".tmp"
    
    async def create_directory(
        self,
        path: Path,
        permissions: int = 0o755
    ) -> bool:
        """Create directory with permissions."""
        try:
            full_path = self._resolve_safe_path(path)
            await aiofiles.os.makedirs(full_path, mode=permissions, exist_ok=True)
            return True
        except OSError as e:
            raise FilesystemError(f"Failed to create directory: {e}")
    
    async def delete_directory(
        self,
        path: Path,
        force: bool = False
    ) -> bool:
        """Delete directory."""
        try:
            full_path = self._resolve_safe_path(path)
            
            if not await self.directory_exists(full_path):
                return False
            
            if force:
                await self._rmtree_async(full_path)
            else:
                await aiofiles.os.rmdir(full_path)
            
            return True
        except OSError as e:
            raise FilesystemError(f"Failed to delete directory: {e}")
    
    async def ensure_directory_exists(self, path: Path) -> bool:
        """Ensure directory exists."""
        return await self.create_directory(path)
    
    async def directory_exists(self, path: Path) -> bool:
        """Check if directory exists."""
        try:
            full_path = self._resolve_safe_path(path)
            return full_path.is_dir()
        except Exception:
            return False
    
    async def get_directory_size(self, path: Path) -> int:
        """Calculate directory size in bytes."""
        full_path = self._resolve_safe_path(path)
        total_size = 0
        
        for dirpath, _, filenames in os.walk(full_path):
            for filename in filenames:
                filepath = Path(dirpath) / filename
                try:
                    stat = await aiofiles.os.stat(filepath)
                    total_size += stat.st_size
                except OSError:
                    pass
        
        return total_size
    
    def create_temp_directory(self, prefix: str = "tmp_") -> Path:
        """Create temporary directory."""
        self.temp_base.mkdir(parents=True, exist_ok=True)
        temp_dir = tempfile.mkdtemp(prefix=prefix, dir=self.temp_base)
        return Path(temp_dir)
    
    async def cleanup_temp_directories(
        self,
        older_than: timedelta = timedelta(hours=24)
    ) -> int:
        """Cleanup old temporary directories."""
        if not self.temp_base.exists():
            return 0
        
        count = 0
        cutoff_time = datetime.now() - older_than
        
        for temp_dir in self.temp_base.iterdir():
            if temp_dir.is_dir():
                try:
                    stat = await aiofiles.os.stat(temp_dir)
                    mtime = datetime.fromtimestamp(stat.st_mtime)
                    
                    if mtime < cutoff_time:
                        await self._rmtree_async(temp_dir)
                        count += 1
                except OSError:
                    pass
        
        return count
    
    def _resolve_safe_path(self, path: Path) -> Path:
        """Resolve path ensuring it's within base directory."""
        if path.is_absolute():
            full_path = path
        else:
            full_path = self.base_path / path
        
        resolved = full_path.resolve()
        
        # Ensure resolved path is within base directory
        try:
            resolved.relative_to(self.base_path)
        except ValueError:
            raise FilesystemError(
                f"Path '{path}' resolves outside base directory"
            )
        
        return resolved
    
    async def _rmtree_async(self, path: Path) -> None:
        """Async version of shutil.rmtree."""
        # For now, use sync version in thread
        await aiofiles.os.run_sync(shutil.rmtree, path)


class FilesystemError(Exception):
    """Filesystem operation error."""
    pass