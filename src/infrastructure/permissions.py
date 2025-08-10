import os
import stat
from pathlib import Path
from typing import Optional, Tuple
import pwd
import grp

from src.core.exceptions import InternalServerError, AuthorizationError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class PermissionManager:
    """Manages POSIX filesystem permissions for repository isolation"""
    
    # Permission modes for different directory types
    NAMESPACE_DIR_MODE = 0o755  # rwxr-xr-x
    REPOSITORY_DIR_MODE = 0o750  # rwxr-x---
    GIT_OBJECT_MODE = 0o640     # rw-r-----
    GIT_DIR_MODE = 0o750        # rwxr-x---
    
    def __init__(self):
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()
        self._original_umask = None
    
    def set_umask(self, mask: int = 0o027) -> None:
        """Set process umask for file creation"""
        self._original_umask = os.umask(mask)
        logger.debug("umask_set", mask=oct(mask))
    
    def restore_umask(self) -> None:
        """Restore original umask"""
        if self._original_umask is not None:
            os.umask(self._original_umask)
            logger.debug("umask_restored", mask=oct(self._original_umask))
            self._original_umask = None
    
    def set_namespace_permissions(self, path: Path) -> None:
        """Set appropriate permissions for a namespace directory"""
        try:
            os.chmod(path, self.NAMESPACE_DIR_MODE)
            
            # Set permissions recursively for repos directory if it exists
            repos_dir = path / "repos"
            if repos_dir.exists():
                os.chmod(repos_dir, self.NAMESPACE_DIR_MODE)
            
            logger.debug(
                "namespace_permissions_set",
                path=str(path),
                mode=oct(self.NAMESPACE_DIR_MODE)
            )
            
        except Exception as e:
            logger.error(
                "namespace_permissions_failed",
                path=str(path),
                error=str(e)
            )
            raise InternalServerError(f"Failed to set namespace permissions: {str(e)}")
    
    def set_repository_permissions(self, path: Path) -> None:
        """Set appropriate permissions for a repository directory"""
        try:
            # Set repository root permissions
            os.chmod(path, self.REPOSITORY_DIR_MODE)
            
            # Set permissions for git directories
            git_dirs = ["objects", "refs", "hooks", "info", "branches"]
            for dir_name in git_dirs:
                dir_path = path / dir_name
                if dir_path.exists():
                    os.chmod(dir_path, self.GIT_DIR_MODE)
                    
                    # Set permissions for files in directory
                    for item in dir_path.rglob("*"):
                        if item.is_file():
                            os.chmod(item, self.GIT_OBJECT_MODE)
                        elif item.is_dir():
                            os.chmod(item, self.GIT_DIR_MODE)
            
            # Set permissions for root-level git files
            git_files = ["HEAD", "config", "description", "packed-refs"]
            for file_name in git_files:
                file_path = path / file_name
                if file_path.exists():
                    os.chmod(file_path, self.GIT_OBJECT_MODE)
            
            logger.debug(
                "repository_permissions_set",
                path=str(path),
                mode=oct(self.REPOSITORY_DIR_MODE)
            )
            
        except Exception as e:
            logger.error(
                "repository_permissions_failed",
                path=str(path),
                error=str(e)
            )
            raise InternalServerError(f"Failed to set repository permissions: {str(e)}")
    
    def check_read_permission(self, path: Path) -> bool:
        """Check if the current process has read permission"""
        try:
            return os.access(path, os.R_OK)
        except Exception as e:
            logger.warning(
                "permission_check_failed",
                path=str(path),
                error=str(e)
            )
            return False
    
    def check_write_permission(self, path: Path) -> bool:
        """Check if the current process has write permission"""
        try:
            return os.access(path, os.W_OK)
        except Exception as e:
            logger.warning(
                "permission_check_failed",
                path=str(path),
                error=str(e)
            )
            return False
    
    def check_execute_permission(self, path: Path) -> bool:
        """Check if the current process has execute permission"""
        try:
            return os.access(path, os.X_OK)
        except Exception as e:
            logger.warning(
                "permission_check_failed",
                path=str(path),
                error=str(e)
            )
            return False
    
    def validate_namespace_access(
        self,
        namespace_path: Path,
        require_write: bool = False
    ) -> None:
        """Validate access to a namespace directory"""
        if not namespace_path.exists():
            raise AuthorizationError(f"Namespace does not exist: {namespace_path}")
        
        if not self.check_read_permission(namespace_path):
            raise AuthorizationError(f"No read access to namespace: {namespace_path}")
        
        if not self.check_execute_permission(namespace_path):
            raise AuthorizationError(f"No execute access to namespace: {namespace_path}")
        
        if require_write and not self.check_write_permission(namespace_path):
            raise AuthorizationError(f"No write access to namespace: {namespace_path}")
    
    def validate_repository_access(
        self,
        repo_path: Path,
        require_write: bool = False
    ) -> None:
        """Validate access to a repository directory"""
        if not repo_path.exists():
            raise AuthorizationError(f"Repository does not exist: {repo_path}")
        
        if not self.check_read_permission(repo_path):
            raise AuthorizationError(f"No read access to repository: {repo_path}")
        
        if not self.check_execute_permission(repo_path):
            raise AuthorizationError(f"No execute access to repository: {repo_path}")
        
        if require_write and not self.check_write_permission(repo_path):
            raise AuthorizationError(f"No write access to repository: {repo_path}")
    
    def get_path_ownership(self, path: Path) -> Tuple[int, int, str, str]:
        """Get ownership information for a path"""
        try:
            stat_info = path.stat()
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            # Try to get username and group name
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                username = str(uid)
            
            try:
                groupname = grp.getgrgid(gid).gr_name
            except KeyError:
                groupname = str(gid)
            
            return uid, gid, username, groupname
            
        except Exception as e:
            logger.error(
                "ownership_check_failed",
                path=str(path),
                error=str(e)
            )
            raise InternalServerError(f"Failed to get ownership info: {str(e)}")
    
    def set_ownership(
        self,
        path: Path,
        uid: Optional[int] = None,
        gid: Optional[int] = None
    ) -> None:
        """Set ownership for a path (requires appropriate privileges)"""
        if uid is None:
            uid = self.current_uid
        if gid is None:
            gid = self.current_gid
        
        try:
            os.chown(path, uid, gid)
            
            logger.debug(
                "ownership_set",
                path=str(path),
                uid=uid,
                gid=gid
            )
            
        except PermissionError as e:
            # This is expected if not running as root
            logger.debug(
                "ownership_set_skipped",
                path=str(path),
                reason="Insufficient privileges"
            )
        except Exception as e:
            logger.error(
                "ownership_set_failed",
                path=str(path),
                error=str(e)
            )
            raise InternalServerError(f"Failed to set ownership: {str(e)}")
    
    def enforce_namespace_isolation(
        self,
        namespace_path: Path,
        owner_uid: Optional[int] = None,
        owner_gid: Optional[int] = None
    ) -> None:
        """Enforce isolation for a namespace and its contents"""
        try:
            # Set namespace permissions
            self.set_namespace_permissions(namespace_path)
            
            # Set ownership if specified (and if we have privileges)
            if owner_uid is not None or owner_gid is not None:
                self.set_ownership(namespace_path, owner_uid, owner_gid)
            
            # Apply to all repositories in namespace
            repos_dir = namespace_path / "repos"
            if repos_dir.exists():
                for repo_dir in repos_dir.iterdir():
                    if repo_dir.is_dir() and repo_dir.name.endswith(".git"):
                        self.set_repository_permissions(repo_dir)
                        if owner_uid is not None or owner_gid is not None:
                            self.set_ownership(repo_dir, owner_uid, owner_gid)
            
            logger.info(
                "namespace_isolation_enforced",
                namespace=namespace_path.name
            )
            
        except Exception as e:
            logger.error(
                "namespace_isolation_failed",
                namespace=namespace_path.name,
                error=str(e)
            )
            raise
    
    def get_permission_string(self, path: Path) -> str:
        """Get human-readable permission string (like ls -l)"""
        try:
            st = path.stat()
            mode = st.st_mode
            
            perms = []
            
            # File type
            if stat.S_ISDIR(mode):
                perms.append('d')
            elif stat.S_ISLNK(mode):
                perms.append('l')
            else:
                perms.append('-')
            
            # Owner permissions
            perms.append('r' if mode & stat.S_IRUSR else '-')
            perms.append('w' if mode & stat.S_IWUSR else '-')
            perms.append('x' if mode & stat.S_IXUSR else '-')
            
            # Group permissions
            perms.append('r' if mode & stat.S_IRGRP else '-')
            perms.append('w' if mode & stat.S_IWGRP else '-')
            perms.append('x' if mode & stat.S_IXGRP else '-')
            
            # Other permissions
            perms.append('r' if mode & stat.S_IROTH else '-')
            perms.append('w' if mode & stat.S_IWOTH else '-')
            perms.append('x' if mode & stat.S_IXOTH else '-')
            
            return ''.join(perms)
            
        except Exception as e:
            logger.error(
                "permission_string_failed",
                path=str(path),
                error=str(e)
            )
            return "----------"