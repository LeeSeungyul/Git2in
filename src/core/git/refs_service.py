"""Git refs handling only"""
from pathlib import Path
from typing import List, Optional, Dict

from .command_executor import GitCommandExecutor
from .command_builder import GitCommandBuilder
from .git_types import GitRef, GitError


class GitRefsService:
    """Handles Git refs operations only"""
    
    def __init__(self, command_executor: GitCommandExecutor):
        """
        Initialize service
        
        Args:
            command_executor: Git command executor
        """
        self.executor = command_executor
        self.builder = GitCommandBuilder()
    
    async def list_refs(
        self, 
        repo_path: Path,
        pattern: Optional[str] = None,
        ref_type: Optional[str] = None
    ) -> List[GitRef]:
        """
        List repository references
        
        Args:
            repo_path: Repository path
            pattern: Pattern to filter refs
            ref_type: Type of refs to list ('heads', 'tags', etc.)
            
        Returns:
            List of GitRef objects
        """
        # Build pattern for specific ref type
        if ref_type:
            pattern = f"refs/{ref_type}/*"
        
        cmd = self.builder.for_each_ref(
            format_string='%(objectname) %(refname) %(refname:lstrip=2)',
            pattern=pattern
        )
        
        result = await self.executor.execute(cmd, cwd=repo_path)
        
        refs = []
        for line in result.stdout.decode().strip().split('\n'):
            if not line:
                continue
            
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                sha, full_ref, short_name = parts
                
                # Extract ref type from full ref
                if full_ref.startswith('refs/'):
                    ref_parts = full_ref.split('/', 2)
                    if len(ref_parts) >= 2:
                        ref_type_name = ref_parts[1]
                        refs.append(GitRef(
                            name=short_name,
                            sha=sha,
                            ref_type=ref_type_name
                        ))
        
        return refs
    
    async def get_ref(self, repo_path: Path, ref_name: str) -> Optional[GitRef]:
        """
        Get a specific reference
        
        Args:
            repo_path: Repository path
            ref_name: Reference name
            
        Returns:
            GitRef or None if not found
        """
        # Try to resolve the ref
        cmd = self.builder.rev_parse(ref_name, verify=True)
        result = await self.executor.execute(cmd, cwd=repo_path)
        
        if not result.success:
            return None
        
        sha = result.stdout.decode().strip()
        
        # Determine ref type
        ref_type = 'heads'  # Default
        if ref_name.startswith('refs/'):
            parts = ref_name.split('/', 2)
            if len(parts) >= 2:
                ref_type = parts[1]
            ref_name = parts[-1] if len(parts) > 2 else ref_name
        
        return GitRef(name=ref_name, sha=sha, ref_type=ref_type)
    
    async def get_symbolic_ref(self, repo_path: Path, name: str = 'HEAD') -> Optional[str]:
        """
        Get symbolic reference target
        
        Args:
            repo_path: Repository path
            name: Symbolic ref name (default: HEAD)
            
        Returns:
            Target reference or None
        """
        cmd = self.builder.symbolic_ref(name)
        result = await self.executor.execute(cmd, cwd=repo_path)
        
        if result.success:
            return result.stdout.decode().strip()
        
        return None
    
    async def get_refs_by_sha(self, repo_path: Path, sha: str) -> List[GitRef]:
        """
        Find all refs pointing to a specific SHA
        
        Args:
            repo_path: Repository path
            sha: Object SHA
            
        Returns:
            List of refs pointing to the SHA
        """
        refs = await self.list_refs(repo_path)
        return [ref for ref in refs if ref.sha == sha]
    
    async def get_head_commit(self, repo_path: Path) -> Optional[str]:
        """
        Get the commit SHA that HEAD points to
        
        Args:
            repo_path: Repository path
            
        Returns:
            Commit SHA or None
        """
        cmd = self.builder.rev_parse('HEAD', verify=True)
        result = await self.executor.execute(cmd, cwd=repo_path)
        
        if result.success:
            return result.stdout.decode().strip()
        
        return None
    
    async def get_default_branch(self, repo_path: Path) -> str:
        """
        Get the default branch name
        
        Args:
            repo_path: Repository path
            
        Returns:
            Default branch name
        """
        # Try to read HEAD symbolic ref
        head_ref = await self.get_symbolic_ref(repo_path, 'HEAD')
        
        if head_ref and head_ref.startswith('refs/heads/'):
            return head_ref[11:]  # Remove 'refs/heads/' prefix
        
        # Fallback to 'main'
        return 'main'
    
    async def ref_exists(self, repo_path: Path, ref_name: str) -> bool:
        """
        Check if a reference exists
        
        Args:
            repo_path: Repository path
            ref_name: Reference to check
            
        Returns:
            True if ref exists
        """
        ref = await self.get_ref(repo_path, ref_name)
        return ref is not None