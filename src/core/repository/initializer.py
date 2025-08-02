"""Repository initialization only (bare Git repo)"""
from pathlib import Path
from typing import Optional, Dict, Any
import os
import stat

from .repository_types import RepositoryInitializationError


class RepositoryInitializer:
    """Handles repository initialization only"""
    
    DEFAULT_DESCRIPTION = "Unnamed repository; edit this file to name the repository."
    DEFAULT_BRANCH = "main"
    
    def init_bare_repository(self, path: Path, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a bare Git repository
        
        Args:
            path: Path where repository should be created
            config: Optional configuration values
            
        Raises:
            RepositoryInitializationError: If initialization fails
        """
        try:
            # Create directory if not exists
            path.mkdir(parents=True, exist_ok=True)
            
            # Create Git directory structure
            self._create_directory_structure(path)
            
            # Write initial files
            self._write_head_file(path, config)
            self._write_config_file(path, config)
            self._write_description_file(path, config)
            
            # Set proper permissions
            self._set_permissions(path)
            
        except Exception as e:
            raise RepositoryInitializationError(str(path), str(e))
    
    def _create_directory_structure(self, path: Path) -> None:
        """Create standard bare repository structure"""
        directories = [
            'branches',
            'hooks',
            'info',
            'objects/info',
            'objects/pack',
            'refs/heads',
            'refs/tags'
        ]
        
        for dir_name in directories:
            (path / dir_name).mkdir(parents=True, exist_ok=True)
    
    def _write_head_file(self, path: Path, config: Optional[Dict[str, Any]] = None) -> None:
        """Write HEAD file pointing to default branch"""
        default_branch = self.DEFAULT_BRANCH
        if config and 'default_branch' in config:
            default_branch = config['default_branch']
        
        head_content = f"ref: refs/heads/{default_branch}\n"
        (path / 'HEAD').write_text(head_content)
    
    def _write_config_file(self, path: Path, config: Optional[Dict[str, Any]] = None) -> None:
        """Write repository config file"""
        config_content = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = true
"""
        
        # Add any custom config
        if config and 'git_config' in config:
            for section, values in config['git_config'].items():
                config_content += f"\n[{section}]\n"
                for key, value in values.items():
                    config_content += f"\t{key} = {value}\n"
        
        (path / 'config').write_text(config_content)
    
    def _write_description_file(self, path: Path, config: Optional[Dict[str, Any]] = None) -> None:
        """Write description file"""
        description = self.DEFAULT_DESCRIPTION
        if config and 'description' in config:
            description = config['description']
        
        (path / 'description').write_text(description + '\n')
    
    def _set_permissions(self, path: Path) -> None:
        """Set appropriate permissions for Git repository"""
        # Repository directory: 755
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        
        # Make hooks executable if present
        hooks_dir = path / 'hooks'
        if hooks_dir.exists():
            for hook in hooks_dir.iterdir():
                if hook.is_file() and not hook.name.endswith('.sample'):
                    os.chmod(hook, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)