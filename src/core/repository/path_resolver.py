"""Repository path calculation and security only"""
from pathlib import Path
from typing import Optional, Tuple

from .repository_types import RepositoryPathError


class RepositoryPathResolver:
    """Handles repository path calculation only"""
    
    def __init__(self, base_path: Path):
        """
        Initialize with base repository path
        
        Args:
            base_path: Base directory for all repositories
        """
        self.base_path = Path(base_path).resolve()
        
        # Ensure base path exists
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def get_repository_path(self, owner: str, repo_name: str) -> Path:
        """
        Calculate full repository path
        
        Args:
            owner: Repository owner username
            repo_name: Repository name
            
        Returns:
            Full path to repository
        """
        # Ensure .git suffix
        if not repo_name.endswith('.git'):
            repo_name = f"{repo_name}.git"
        
        # Build path: base/owner/repo.git
        repo_path = self.base_path / owner / repo_name
        
        return repo_path
    
    def validate_path_security(self, path: Path) -> bool:
        """
        Validate path is within base directory (prevent traversal)
        
        Args:
            path: Path to validate
            
        Returns:
            True if path is safe
        """
        try:
            # Resolve to absolute path
            resolved = path.resolve()
            
            # Check if path is within base directory
            resolved.relative_to(self.base_path)
            
            return True
        except (ValueError, RuntimeError):
            return False
    
    def parse_repository_path(self, path: Path) -> Optional[Tuple[str, str]]:
        """
        Extract owner and repo name from path
        
        Args:
            path: Repository path
            
        Returns:
            Tuple of (owner, repo_name) or None
        """
        try:
            relative = path.relative_to(self.base_path)
            parts = relative.parts
            
            if len(parts) == 2:
                owner = parts[0]
                repo_name = parts[1]
                
                # Remove .git suffix
                if repo_name.endswith('.git'):
                    repo_name = repo_name[:-4]
                
                return (owner, repo_name)
        except ValueError:
            pass
        
        return None
    
    def secure_path_join(self, *parts: str) -> Path:
        """
        Securely join path parts preventing traversal
        
        Args:
            parts: Path parts to join
            
        Returns:
            Joined path
            
        Raises:
            RepositoryPathError: If resulting path is outside base
        """
        # Clean each part
        cleaned_parts = []
        for part in parts:
            # Remove any directory traversal attempts
            cleaned = part.replace('..', '').replace('~', '')
            
            # Remove leading slashes
            cleaned = cleaned.lstrip('/')
            
            cleaned_parts.append(cleaned)
        
        # Join with base
        full_path = self.base_path.joinpath(*cleaned_parts).resolve()
        
        # Verify still within base
        try:
            full_path.relative_to(self.base_path)
        except ValueError:
            raise RepositoryPathError(
                str(full_path), 
                "Path traversal detected"
            )
        
        return full_path