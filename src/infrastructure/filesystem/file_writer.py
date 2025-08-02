"""File writing operations module."""
import aiofiles
import tempfile
from pathlib import Path
from typing import AsyncIterator
import aiofiles.os


class FileWriter:
    """Handles file writing operations only."""
    
    def __init__(self, base_path: Path):
        self.base_path = Path(base_path).resolve()
    
    async def write_file(
        self,
        path: Path,
        content: bytes,
        atomic: bool = True
    ) -> bool:
        """Write content to file."""
        full_path = self._resolve_safe_path(path)
        
        try:
            # Ensure parent directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            if atomic:
                # Write to temporary file first
                with tempfile.NamedTemporaryFile(
                    dir=full_path.parent,
                    delete=False
                ) as tmp_file:
                    tmp_path = Path(tmp_file.name)
                
                # Write content
                async with aiofiles.open(tmp_path, 'wb') as f:
                    await f.write(content)
                
                # Atomic rename
                await aiofiles.os.rename(tmp_path, full_path)
            else:
                # Direct write
                async with aiofiles.open(full_path, 'wb') as f:
                    await f.write(content)
            
            return True
            
        except PermissionError:
            raise FilesystemError(f"Permission denied: {path}")
        except Exception as e:
            raise FilesystemError(f"Failed to write file: {e}")
    
    async def write_file_stream(
        self,
        path: Path,
        stream: AsyncIterator[bytes]
    ) -> bool:
        """Write stream to file."""
        full_path = self._resolve_safe_path(path)
        
        try:
            # Ensure parent directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first
            with tempfile.NamedTemporaryFile(
                dir=full_path.parent,
                delete=False
            ) as tmp_file:
                tmp_path = Path(tmp_file.name)
            
            # Write stream content
            async with aiofiles.open(tmp_path, 'wb') as f:
                async for chunk in stream:
                    await f.write(chunk)
            
            # Atomic rename
            await aiofiles.os.rename(tmp_path, full_path)
            
            return True
            
        except PermissionError:
            raise FilesystemError(f"Permission denied: {path}")
        except Exception as e:
            raise FilesystemError(f"Failed to write file stream: {e}")
    
    async def copy_file(self, source: Path, destination: Path) -> bool:
        """Copy file from source to destination."""
        source_path = self._resolve_safe_path(source)
        dest_path = self._resolve_safe_path(destination)
        
        try:
            # Ensure source exists
            if not source_path.is_file():
                raise FilesystemError(f"Source file not found: {source}")
            
            # Ensure destination directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            async with aiofiles.open(source_path, 'rb') as src:
                async with aiofiles.open(dest_path, 'wb') as dst:
                    while True:
                        chunk = await src.read(8192)
                        if not chunk:
                            break
                        await dst.write(chunk)
            
            # Copy permissions
            source_stat = await aiofiles.os.stat(source_path)
            await aiofiles.os.chmod(dest_path, source_stat.st_mode)
            
            return True
            
        except Exception as e:
            raise FilesystemError(f"Failed to copy file: {e}")
    
    async def move_file(self, source: Path, destination: Path) -> bool:
        """Move file from source to destination."""
        source_path = self._resolve_safe_path(source)
        dest_path = self._resolve_safe_path(destination)
        
        try:
            # Ensure source exists
            if not source_path.is_file():
                raise FilesystemError(f"Source file not found: {source}")
            
            # Ensure destination directory exists
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file
            await aiofiles.os.rename(source_path, dest_path)
            
            return True
            
        except Exception as e:
            raise FilesystemError(f"Failed to move file: {e}")
    
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