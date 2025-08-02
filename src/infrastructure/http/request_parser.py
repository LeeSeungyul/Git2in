"""Git HTTP request parsing module."""
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs

from src.core.git.git_types import GitService


class GitHttpRequestParser:
    """Parses Git HTTP protocol requests only."""
    
    # Git service patterns
    SERVICE_PATTERNS = {
        GitService.UPLOAD_PACK: re.compile(r'/git-upload-pack$'),
        GitService.RECEIVE_PACK: re.compile(r'/git-receive-pack$'),
    }
    
    # Repository path pattern
    REPO_PATH_PATTERN = re.compile(
        r'^/(?P<owner>[a-zA-Z0-9_-]+)/(?P<repo>[a-zA-Z0-9._-]+?)(?:\.git)?(?P<suffix>/.+)?$'
    )
    
    @classmethod
    def parse_git_service(cls, path: str) -> Optional[GitService]:
        """Parse Git service from request path."""
        # Check info/refs query parameter
        parsed = urlparse(path)
        query_params = parse_qs(parsed.query)
        
        if 'service' in query_params:
            service_name = query_params['service'][0]
            if service_name == 'git-upload-pack':
                return GitService.UPLOAD_PACK
            elif service_name == 'git-receive-pack':
                return GitService.RECEIVE_PACK
        
        # Check path patterns
        for service, pattern in cls.SERVICE_PATTERNS.items():
            if pattern.search(path):
                return service
        
        return None
    
    @classmethod
    def parse_repository_path(cls, path: str) -> Optional[Tuple[str, str]]:
        """Parse owner and repository name from path."""
        # Remove query string
        path = urlparse(path).path
        
        match = cls.REPO_PATH_PATTERN.match(path)
        if match:
            owner = match.group('owner')
            repo = match.group('repo')
            
            # Ensure .git suffix
            if not repo.endswith('.git'):
                repo = f"{repo}.git"
            
            return (owner, repo)
        
        return None
    
    @classmethod
    def parse_auth_header(cls, auth_header: str) -> Optional[dict]:
        """Parse authorization header."""
        if not auth_header:
            return None
        
        parts = auth_header.split(' ', 1)
        if len(parts) != 2:
            return None
        
        auth_type, credentials = parts
        auth_type = auth_type.lower()
        
        if auth_type == 'basic':
            # Basic auth will be decoded by auth extractor
            return {
                'type': 'basic',
                'credentials': credentials
            }
        elif auth_type == 'bearer':
            return {
                'type': 'bearer',
                'token': credentials
            }
        
        return None
    
    @classmethod
    def is_git_request(cls, path: str, headers: dict) -> bool:
        """Check if this is a Git protocol request."""
        # Check for Git service
        if cls.parse_git_service(path):
            return True
        
        # Check for Git user agent
        user_agent = headers.get('user-agent', '').lower()
        if 'git/' in user_agent:
            return True
        
        # Check for Git content type
        content_type = headers.get('content-type', '').lower()
        if 'git' in content_type:
            return True
        
        return False