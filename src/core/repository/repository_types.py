"""Repository-related type definitions and exceptions"""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from datetime import datetime


@dataclass
class ValidationResult:
    """Result of repository validation"""
    is_valid: bool
    errors: List[str]


@dataclass
class RepositoryInfo:
    """Repository information"""
    path: Path
    size_bytes: int
    object_count: int
    default_branch: str
    last_modified: datetime
    is_bare: bool


# Repository-specific exceptions
class RepositoryError(Exception):
    """Base class for repository errors"""
    pass


class RepositoryNotFoundError(RepositoryError):
    """Repository does not exist"""
    def __init__(self, repo_id: str):
        super().__init__(f"Repository not found: {repo_id}")
        self.repo_id = repo_id


class RepositoryAlreadyExistsError(RepositoryError):
    """Repository already exists"""
    def __init__(self, repo_id: str):
        super().__init__(f"Repository already exists: {repo_id}")
        self.repo_id = repo_id


class InvalidRepositoryNameError(RepositoryError):
    """Invalid repository name"""
    def __init__(self, name: str, reason: str):
        super().__init__(f"Invalid repository name '{name}': {reason}")
        self.name = name
        self.reason = reason


class RepositoryInitializationError(RepositoryError):
    """Failed to initialize repository"""
    def __init__(self, path: str, reason: str):
        super().__init__(f"Failed to initialize repository at '{path}': {reason}")
        self.path = path
        self.reason = reason


class RepositoryPathError(RepositoryError):
    """Repository path security error"""
    def __init__(self, path: str, reason: str):
        super().__init__(f"Invalid repository path '{path}': {reason}")
        self.path = path
        self.reason = reason