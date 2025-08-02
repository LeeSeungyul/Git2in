"""File reading operations module."""
import aiofiles
import mimetypes
from pathlib import Path
from typing import AsyncIterator, Optional
from dataclasses import dataclass
import aiofiles.os


@dataclass
class FileInfo:
    """File information container."""
    path: Path
    size: int
    mime_type: Optional[str]
    exists: bool


class FileReader:
    """Handles file reading operations only."""
    
    def __init__(self, base_path: Path):
        self.base_path = Path(base_path).resolve()
    
    async def read_file(self, path: Path) -> bytes:
        """Read entire file content."""
        full_path = self._resolve_safe_path(path)
        
        try:
            async with aiofiles.open(full_path, 'rb') as f:
                return await f.read()
        except FileNotFoundError:
            raise FilesystemError(f"File not found: {path}")
        except PermissionError:
            raise FilesystemError(f"Permission denied: {path}")
        except Exception as e:
            raise FilesystemError(f"Failed to read file: {e}")
    
    async def read_file_stream(
        self,
        path: Path,
        chunk_size: int = 8192
    ) -> AsyncIterator[bytes]:
        """Read file in chunks for streaming."""
        full_path = self._resolve_safe_path(path)
        
        try:
            async with aiofiles.open(full_path, 'rb') as f:
                while True:
                    chunk = await f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except FileNotFoundError:
            raise FilesystemError(f"File not found: {path}")
        except PermissionError:
            raise FilesystemError(f"Permission denied: {path}")
        except Exception as e:
            raise FilesystemError(f"Failed to read file: {e}")
    
    async def get_file_info(self, path: Path) -> FileInfo:
        """Get file information."""
        full_path = self._resolve_safe_path(path)
        
        try:
            if not full_path.exists():
                return FileInfo(
                    path=path,
                    size=0,
                    mime_type=None,
                    exists=False
                )
            
            stat = await aiofiles.os.stat(full_path)
            mime_type, _ = mimetypes.guess_type(str(full_path))
            
            return FileInfo(
                path=path,
                size=stat.st_size,
                mime_type=mime_type,
                exists=True
            )
        except Exception as e:
            raise FilesystemError(f"Failed to get file info: {e}")
    
    async def file_exists(self, path: Path) -> bool:
        """Check if file exists."""
        try:
            full_path = self._resolve_safe_path(path)
            return full_path.is_file()
        except Exception:
            return False
    
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


class FilesystemError(Exception):
    """Filesystem operation error."""
    pass