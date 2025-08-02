"""Git-related type definitions and exceptions"""
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class GitService(str, Enum):
    """Git services"""
    UPLOAD_PACK = "git-upload-pack"
    RECEIVE_PACK = "git-receive-pack"


@dataclass
class CommandResult:
    """Result of Git command execution"""
    exit_code: int
    stdout: bytes
    stderr: bytes
    
    @property
    def success(self) -> bool:
        return self.exit_code == 0


@dataclass
class RefUpdate:
    """Reference update information"""
    ref_name: str
    old_sha: str
    new_sha: str
    
    @property
    def is_delete(self) -> bool:
        return self.new_sha == '0' * 40
    
    @property
    def is_create(self) -> bool:
        return self.old_sha == '0' * 40
    
    @property
    def is_update(self) -> bool:
        return not (self.is_create or self.is_delete)


@dataclass
class GitRef:
    """Git reference information"""
    name: str
    sha: str
    ref_type: str  # 'heads', 'tags', etc.
    
    @property
    def full_name(self) -> str:
        return f"refs/{self.ref_type}/{self.name}"


# Git-specific exceptions
class GitError(Exception):
    """Base class for Git errors"""
    pass


class GitCommandError(GitError):
    """Git command execution failed"""
    def __init__(self, command: str, exit_code: int, stderr: str):
        super().__init__(f"Git command '{command}' failed with exit code {exit_code}: {stderr}")
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class GitProtocolError(GitError):
    """Git protocol error"""
    pass


class GitTimeoutError(GitError):
    """Git operation timed out"""
    def __init__(self, command: str, timeout: int):
        super().__init__(f"Git command '{command}' timed out after {timeout} seconds")
        self.command = command
        self.timeout = timeout


class GitSecurityError(GitError):
    """Security violation in Git operation"""
    pass