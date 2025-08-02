"""Git command construction only"""
from typing import List, Optional, Dict, Any
from pathlib import Path

from .git_types import GitService


class GitCommandBuilder:
    """Handles Git command construction only"""
    
    @staticmethod
    def init_bare(path: Path) -> List[str]:
        """
        Build command to initialize bare repository
        
        Args:
            path: Repository path
            
        Returns:
            Command arguments
        """
        return ['init', '--bare', str(path)]
    
    @staticmethod
    def update_server_info() -> List[str]:
        """
        Build command to update server info
        
        Returns:
            Command arguments
        """
        return ['update-server-info']
    
    @staticmethod
    def upload_pack(repo_path: Path, stateless_rpc: bool = True, advertise_refs: bool = False) -> List[str]:
        """
        Build upload-pack command
        
        Args:
            repo_path: Repository path
            stateless_rpc: Use stateless RPC mode
            advertise_refs: Advertise refs only
            
        Returns:
            Command arguments
        """
        cmd = ['upload-pack']
        
        if stateless_rpc:
            cmd.append('--stateless-rpc')
        
        if advertise_refs:
            cmd.append('--advertise-refs')
        
        cmd.append(str(repo_path))
        
        return cmd
    
    @staticmethod
    def receive_pack(repo_path: Path, stateless_rpc: bool = True) -> List[str]:
        """
        Build receive-pack command
        
        Args:
            repo_path: Repository path
            stateless_rpc: Use stateless RPC mode
            
        Returns:
            Command arguments
        """
        cmd = ['receive-pack']
        
        if stateless_rpc:
            cmd.append('--stateless-rpc')
        
        cmd.append(str(repo_path))
        
        return cmd
    
    @staticmethod
    def for_each_ref(format_string: Optional[str] = None, pattern: Optional[str] = None) -> List[str]:
        """
        Build for-each-ref command
        
        Args:
            format_string: Output format
            pattern: Ref pattern to match
            
        Returns:
            Command arguments
        """
        cmd = ['for-each-ref']
        
        if format_string:
            cmd.extend(['--format', format_string])
        
        if pattern:
            cmd.append(pattern)
        
        return cmd
    
    @staticmethod
    def show_ref(heads: bool = False, tags: bool = False) -> List[str]:
        """
        Build show-ref command
        
        Args:
            heads: Show only heads
            tags: Show only tags
            
        Returns:
            Command arguments
        """
        cmd = ['show-ref']
        
        if heads:
            cmd.append('--heads')
        
        if tags:
            cmd.append('--tags')
        
        return cmd
    
    @staticmethod
    def rev_parse(rev: str, verify: bool = True) -> List[str]:
        """
        Build rev-parse command
        
        Args:
            rev: Revision to parse
            verify: Verify the object exists
            
        Returns:
            Command arguments
        """
        cmd = ['rev-parse']
        
        if verify:
            cmd.append('--verify')
        
        cmd.append(rev)
        
        return cmd
    
    @staticmethod
    def cat_file(object_type: Optional[str] = None, sha: str = None, check_exists: bool = False) -> List[str]:
        """
        Build cat-file command
        
        Args:
            object_type: Object type to show (blob, tree, commit, tag)
            sha: Object SHA to examine
            check_exists: Just check if object exists
            
        Returns:
            Command arguments
        """
        cmd = ['cat-file']
        
        if check_exists:
            cmd.append('-e')
        elif object_type:
            cmd.append(object_type)
        
        if sha:
            cmd.append(sha)
        
        return cmd
    
    @staticmethod
    def ls_tree(tree_ish: str, recursive: bool = False, name_only: bool = False) -> List[str]:
        """
        Build ls-tree command
        
        Args:
            tree_ish: Tree object to list
            recursive: List recursively
            name_only: Show only names
            
        Returns:
            Command arguments
        """
        cmd = ['ls-tree']
        
        if recursive:
            cmd.append('-r')
        
        if name_only:
            cmd.append('--name-only')
        
        cmd.append(tree_ish)
        
        return cmd
    
    @staticmethod
    def count_objects(verbose: bool = True) -> List[str]:
        """
        Build count-objects command
        
        Args:
            verbose: Show verbose output
            
        Returns:
            Command arguments
        """
        cmd = ['count-objects']
        
        if verbose:
            cmd.append('-v')
        
        return cmd
    
    @staticmethod
    def config(key: str, value: Optional[str] = None, get: bool = False) -> List[str]:
        """
        Build config command
        
        Args:
            key: Config key
            value: Config value (for setting)
            get: Get value instead of setting
            
        Returns:
            Command arguments
        """
        cmd = ['config']
        
        if get:
            cmd.append('--get')
        
        cmd.append(key)
        
        if value is not None and not get:
            cmd.append(value)
        
        return cmd
    
    @staticmethod
    def symbolic_ref(name: str, ref: Optional[str] = None) -> List[str]:
        """
        Build symbolic-ref command
        
        Args:
            name: Symbolic ref name
            ref: Target ref (for setting)
            
        Returns:
            Command arguments
        """
        cmd = ['symbolic-ref', name]
        
        if ref:
            cmd.append(ref)
        
        return cmd