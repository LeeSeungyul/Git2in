"""Pytest configuration and fixtures"""

import os
import shutil
import tempfile
import asyncio
from pathlib import Path
from typing import Generator, AsyncGenerator
import subprocess

import pytest
import pytest_asyncio
from httpx import AsyncClient
from fastapi.testclient import TestClient

from src.main import app
from src.core.config import settings
from src.infrastructure.filesystem import FilesystemManager
from src.core.models import Namespace, Repository, User
from src.core.services.repository import RepositoryService


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_base_dir() -> Generator[Path, None, None]:
    """Create a temporary base directory for test repositories"""
    temp_dir = tempfile.mkdtemp(prefix="git2in_test_")
    base_dir = Path(temp_dir)
    
    # Override settings for testing
    original_base_path = settings.repository_base_path
    settings.repository_base_path = base_dir
    
    yield base_dir
    
    # Cleanup
    settings.repository_base_path = original_base_path
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def filesystem_manager(test_base_dir: Path) -> FilesystemManager:
    """Create a filesystem manager for tests"""
    return FilesystemManager()


@pytest.fixture
def repository_service(filesystem_manager: FilesystemManager) -> RepositoryService:
    """Create a repository service for tests"""
    return RepositoryService(filesystem_manager)


@pytest.fixture
def test_namespace() -> Namespace:
    """Create a test namespace"""
    return Namespace(
        name="test-namespace",
        description="Test namespace for integration tests",
        owner_id="00000000-0000-0000-0000-000000000000"
    )


@pytest.fixture
def test_repository() -> Repository:
    """Create a test repository"""
    return Repository(
        name="test-repo",
        namespace_name="test-namespace",
        description="Test repository for integration tests",
        owner_id="00000000-0000-0000-0000-000000000000"
    )


@pytest.fixture
def test_user() -> User:
    """Create a test user"""
    return User(
        username="testuser",
        email="test@example.com",
        is_active=True
    )


@pytest.fixture
async def initialized_repo(
    filesystem_manager: FilesystemManager,
    repository_service: RepositoryService,
    test_namespace: Namespace,
    test_repository: Repository
) -> AsyncGenerator[Path, None]:
    """Create an initialized Git repository for testing"""
    
    # Create namespace directory
    filesystem_manager.create_namespace_directory(test_namespace.name)
    
    # Create repository
    repo_path = await repository_service.create_repository(
        test_namespace,
        test_repository
    )
    
    # Add some test content
    test_file = repo_path / "test.txt"
    test_file.write_text("Hello, Git2in!")
    
    # Initialize with test commit
    subprocess.run(
        ["git", "init"],
        cwd=str(repo_path.parent),
        check=True,
        capture_output=True
    )
    
    subprocess.run(
        ["git", "add", "."],
        cwd=str(repo_path.parent),
        check=True,
        capture_output=True
    )
    
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(repo_path.parent),
        check=True,
        capture_output=True
    )
    
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(repo_path.parent),
        check=True,
        capture_output=True
    )
    
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=str(repo_path.parent),
        check=True,
        capture_output=True
    )
    
    # Now clone to bare repository
    bare_repo_path = filesystem_manager.get_repository_path(
        test_namespace.name,
        f"{test_repository.name}.git"
    )
    
    subprocess.run(
        ["git", "clone", "--bare", str(repo_path.parent), str(bare_repo_path)],
        check=True,
        capture_output=True
    )
    
    yield bare_repo_path
    
    # Cleanup is handled by test_base_dir fixture


@pytest.fixture
def client() -> TestClient:
    """Create a FastAPI test client"""
    return TestClient(app)


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def git_client_headers() -> dict:
    """Common headers sent by Git clients"""
    return {
        "User-Agent": "git/2.39.0",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Git-Protocol": "version=2"
    }


@pytest.fixture
def mock_git_http_backend(monkeypatch):
    """Mock git-http-backend for testing without actual Git"""
    
    class MockGitBackend:
        def __init__(self, *args, **kwargs):
            self.calls = []
            
        async def __aenter__(self):
            return self
            
        async def __aexit__(self, *args):
            pass
            
        async def execute(self, **kwargs):
            self.calls.append(kwargs)
            return self
            
        async def write_input(self, data):
            pass
            
        async def close_input(self):
            pass
            
        async def read_output(self):
            # Simulate git-http-backend output
            yield b"001e# service=git-upload-pack\n"
            yield b"0000"
            yield b"00a0f5d4e3c2b1a09876543210fedcba9876543210 HEAD\x00multi_ack thin-pack side-band ofs-delta shallow no-progress include-tag multi_ack_detailed no-done agent=git/2.39.0\n"
            yield b"003ff5d4e3c2b1a09876543210fedcba9876543210 refs/heads/main\n"
            yield b"0000"
            
        async def read_stderr(self):
            return ""
            
        async def wait(self):
            return 0
    
    monkeypatch.setattr(
        "src.api.git_http.GitBackendProcess",
        MockGitBackend
    )
    
    return MockGitBackend


@pytest.fixture
def test_repository_path(test_base_dir: Path) -> Path:
    """Create a test repository path"""
    repo_path = test_base_dir / "repositories" / "test-namespace" / "test-repo.git"
    repo_path.mkdir(parents=True, exist_ok=True)
    
    # Initialize as bare repository
    subprocess.run(
        ["git", "init", "--bare"],
        cwd=str(repo_path),
        check=True,
        capture_output=True
    )
    
    return repo_path