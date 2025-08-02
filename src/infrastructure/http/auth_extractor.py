"""Authentication header extraction module."""
import base64
from typing import Optional, Tuple
from enum import Enum


class AuthMethod(str, Enum):
    """Authentication methods."""
    BASIC = "basic"
    BEARER = "bearer"
    PAT = "pat"
    NONE = "none"


class AuthExtractor:
    """Handles authentication header extraction only."""
    
    @classmethod
    def extract_bearer_token(cls, header: str) -> Optional[str]:
        """Extract Bearer token from authorization header."""
        if not header:
            return None
        
        parts = header.split(' ', 1)
        if len(parts) != 2:
            return None
        
        auth_type, token = parts
        if auth_type.lower() == 'bearer':
            return token
        
        return None
    
    @classmethod
    def extract_basic_auth(cls, header: str) -> Optional[Tuple[str, str]]:
        """Extract username and password from Basic auth header."""
        if not header:
            return None
        
        parts = header.split(' ', 1)
        if len(parts) != 2:
            return None
        
        auth_type, credentials = parts
        if auth_type.lower() != 'basic':
            return None
        
        try:
            # Decode base64
            decoded = base64.b64decode(credentials).decode('utf-8')
            
            # Split username:password
            if ':' not in decoded:
                return None
            
            username, password = decoded.split(':', 1)
            return (username, password)
            
        except (ValueError, UnicodeDecodeError):
            return None
    
    @classmethod
    def extract_pat_token(cls, header: str) -> Optional[str]:
        """Extract PAT token from authorization header."""
        # PAT can be in Bearer format or Basic auth with token as password
        
        # Try Bearer first
        token = cls.extract_bearer_token(header)
        if token:
            return token
        
        # Try Basic auth with token as password
        basic_auth = cls.extract_basic_auth(header)
        if basic_auth:
            username, password = basic_auth
            # Git clients often send token as both username and password
            # or username 'token' with PAT as password
            if username in ['token', 'x-token-auth', password]:
                return password
        
        return None
    
    @classmethod
    def get_auth_method(cls, headers: dict) -> AuthMethod:
        """Determine authentication method from request headers."""
        auth_header = headers.get('authorization', '').strip()
        
        if not auth_header:
            return AuthMethod.NONE
        
        auth_type = auth_header.split(' ', 1)[0].lower()
        
        if auth_type == 'bearer':
            return AuthMethod.BEARER
        elif auth_type == 'basic':
            # Check if it's actually a PAT in Basic auth
            basic_auth = cls.extract_basic_auth(auth_header)
            if basic_auth:
                username, _ = basic_auth
                if username in ['token', 'x-token-auth']:
                    return AuthMethod.PAT
            return AuthMethod.BASIC
        
        return AuthMethod.NONE