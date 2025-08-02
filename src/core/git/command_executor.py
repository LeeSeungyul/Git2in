"""Safe Git command execution only"""
import subprocess
import asyncio
from typing import List, Optional, AsyncIterator, Dict
from pathlib import Path
import os

from .git_types import CommandResult, GitCommandError, GitTimeoutError, GitSecurityError


class GitCommandExecutor:
    """Handles Git command execution only"""
    
    # Whitelisted Git commands
    ALLOWED_COMMANDS = {
        'init', 'upload-pack', 'receive-pack', 'update-server-info',
        'rev-list', 'cat-file', 'ls-tree', 'show-ref', 'rev-parse',
        'for-each-ref', 'symbolic-ref', 'pack-objects', 'config',
        'count-objects'
    }
    
    def __init__(self, git_binary: str = 'git', timeout: int = 300):
        """
        Initialize executor
        
        Args:
            git_binary: Path to git binary
            timeout: Command timeout in seconds
        """
        self.git_binary = git_binary
        self.timeout = timeout
    
    async def execute(
        self,
        args: List[str],
        cwd: Optional[Path] = None,
        input_data: Optional[bytes] = None,
        env: Optional[Dict[str, str]] = None
    ) -> CommandResult:
        """
        Execute Git command safely
        
        Args:
            args: Git command arguments (without 'git')
            cwd: Working directory
            input_data: Input to send to command
            env: Environment variables
            
        Returns:
            CommandResult with output
            
        Raises:
            GitSecurityError: If command is not allowed
            GitCommandError: If command fails
            GitTimeoutError: If command times out
        """
        # Validate command
        if not args or args[0] not in self.ALLOWED_COMMANDS:
            raise GitSecurityError(f"Command not allowed: {args[0] if args else 'empty'}")
        
        # Validate arguments for security
        self._validate_args_security(args)
        
        # Build full command
        cmd = [self.git_binary] + args
        
        # Merge environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        # Ensure safe Git environment
        cmd_env.update({
            'GIT_TERMINAL_PROMPT': '0',  # Disable prompts
            'GIT_ASKPASS': '/bin/echo',   # Disable password prompts
            'LC_ALL': 'C',                # Consistent output
        })
        
        try:
            # Run command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=cmd_env
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data),
                timeout=self.timeout
            )
            
            result = CommandResult(
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr
            )
            
            # Check for Git errors
            if not result.success:
                raise GitCommandError(
                    ' '.join(args),
                    result.exit_code,
                    stderr.decode('utf-8', errors='replace')
                )
            
            return result
            
        except asyncio.TimeoutError:
            # Kill process on timeout
            process.kill()
            await process.wait()
            raise GitTimeoutError(' '.join(args), self.timeout)
    
    async def stream_command(
        self,
        args: List[str],
        cwd: Path,
        input_stream: Optional[AsyncIterator[bytes]] = None,
        env: Optional[Dict[str, str]] = None
    ) -> AsyncIterator[bytes]:
        """
        Stream command output for large operations
        
        Args:
            args: Git command arguments
            cwd: Working directory
            input_stream: Async iterator of input chunks
            env: Environment variables
            
        Yields:
            Output chunks
        """
        if not args or args[0] not in self.ALLOWED_COMMANDS:
            raise GitSecurityError(f"Command not allowed: {args[0]}")
        
        # Validate arguments for security
        self._validate_args_security(args)
        
        cmd = [self.git_binary] + args
        
        # Merge environment
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        # Ensure safe Git environment
        cmd_env.update({
            'GIT_TERMINAL_PROMPT': '0',
            'GIT_ASKPASS': '/bin/echo',
            'LC_ALL': 'C',
        })
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE if input_stream else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=cmd_env
        )
        
        async def write_input():
            """Write input stream to process"""
            if input_stream and process.stdin:
                try:
                    async for chunk in input_stream:
                        process.stdin.write(chunk)
                        await process.stdin.drain()
                finally:
                    process.stdin.close()
                    await process.stdin.wait_closed()
        
        # Start writing input
        input_task = asyncio.create_task(write_input())
        
        try:
            # Stream output
            while True:
                chunk = await process.stdout.read(8192)
                if not chunk:
                    break
                yield chunk
            
            # Wait for process to complete
            await process.wait()
            
            # Check for errors
            if process.returncode != 0:
                stderr = await process.stderr.read()
                raise GitCommandError(
                    ' '.join(args),
                    process.returncode,
                    stderr.decode('utf-8', errors='replace')
                )
                
        finally:
            # Ensure input task completes
            await input_task
            # Kill process if still running
            if process.returncode is None:
                process.kill()
                await process.wait()
    
    def _validate_args_security(self, args: List[str]) -> None:
        """
        Validate command arguments for security
        
        Args:
            args: Command arguments to validate
            
        Raises:
            GitSecurityError: If arguments are unsafe
        """
        # Check for shell metacharacters
        dangerous_chars = ['&', '|', ';', '$', '`', '\n', '\r', '(', ')', '{', '}', '[', ']', '<', '>']
        
        for arg in args:
            for char in dangerous_chars:
                if char in arg:
                    raise GitSecurityError(f"Unsafe character '{char}' in argument: {arg}")
            
            # Check for command injection attempts
            if arg.startswith('--') and '=' in arg:
                # Allow safe options like --format=...
                option_name = arg.split('=', 1)[0]
                if option_name not in ['--format', '--git-dir', '--work-tree']:
                    raise GitSecurityError(f"Unsafe option: {arg}")