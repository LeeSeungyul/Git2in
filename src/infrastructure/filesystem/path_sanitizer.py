"""Path security validation module."""
import re
from pathlib import Path
from typing import Optional


class PathSanitizer:
    """Handles path security validation only."""
    
    # Dangerous path patterns
    DANGEROUS_PATTERNS = [
        r'\.\.',  # Parent directory
        r'^~',    # Home directory
        r'^\/',   # Absolute path
        r'\\',    # Backslash (Windows paths)
    ]
    
    # Valid filename pattern
    VALID_FILENAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
    
    @classmethod
    def is_safe_path(cls, path: Path, base_path: Path) -> bool:
        """Check if path is safe."""
        try:
            # Convert to string for pattern matching
            path_str = str(path)
            
            # Check dangerous patterns
            for pattern in cls.DANGEROUS_PATTERNS:
                if re.search(pattern, path_str):
                    return False
            
            # Resolve and check if within base
            if path.is_absolute():
                resolved = path.resolve()
            else:
                resolved = (base_path / path).resolve()
            
            # Must be within base path
            resolved.relative_to(base_path.resolve())
            return True
            
        except (ValueError, RuntimeError):
            return False
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize filename for safe storage."""
        # Remove any path separators
        filename = filename.replace('/', '').replace('\\', '')
        
        # Replace spaces with underscores
        filename = filename.replace(' ', '_')
        
        # Remove any non-alphanumeric characters except ._-
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Ensure doesn't start with dot
        filename = filename.lstrip('.')
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            max_name_len = 250 - len(ext)
            filename = f"{name[:max_name_len]}.{ext}" if ext else name[:255]
        
        return filename or 'unnamed'
    
    @classmethod
    def validate_repository_path(cls, repo_path: Path) -> bool:
        """Validate repository path format."""
        try:
            parts = repo_path.parts
            
            # Should be owner/repo.git format
            if len(parts) != 2:
                return False
            
            owner, repo = parts
            
            # Validate owner name
            if not cls.VALID_FILENAME.match(owner):
                return False
            
            # Validate repo name (should end with .git)
            if not repo.endswith('.git'):
                return False
            
            repo_name = repo[:-4]  # Remove .git
            if not cls.VALID_FILENAME.match(repo_name):
                return False
            
            return True
            
        except Exception:
            return False
    
    @classmethod
    def resolve_safe_path(
        cls,
        user_input: str,
        base_path: Path
    ) -> Optional[Path]:
        """Resolve user input to safe path."""
        try:
            # Basic cleaning
            cleaned = user_input.strip()
            
            # Empty input
            if not cleaned:
                return None
            
            # Create path
            path = Path(cleaned)
            
            # Check if safe
            if not cls.is_safe_path(path, base_path):
                return None
            
            # Resolve relative to base
            if path.is_absolute():
                resolved = path.resolve()
            else:
                resolved = (base_path / path).resolve()
            
            # Final safety check
            resolved.relative_to(base_path.resolve())
            
            return resolved
            
        except Exception:
            return None