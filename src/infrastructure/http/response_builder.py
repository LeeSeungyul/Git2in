"""Git HTTP response building module."""
from typing import Dict, Any

from src.core.git.git_types import GitService


class GitHttpResponseBuilder:
    """Builds Git HTTP protocol responses only."""
    
    # Git service content types
    SERVICE_CONTENT_TYPES = {
        GitService.UPLOAD_PACK: {
            'advertisement': 'application/x-git-upload-pack-advertisement',
            'result': 'application/x-git-upload-pack-result'
        },
        GitService.RECEIVE_PACK: {
            'advertisement': 'application/x-git-receive-pack-advertisement',
            'result': 'application/x-git-receive-pack-result'
        }
    }
    
    @classmethod
    def build_service_advertisement(
        cls,
        service: GitService,
        refs_data: bytes
    ) -> Dict[str, Any]:
        """Build service advertisement response."""
        content_type = cls.SERVICE_CONTENT_TYPES[service]['advertisement']
        
        # Add service header
        service_line = cls._encode_pkt_line(f"# service={service.value}\n")
        flush_pkt = b"0000"
        
        body = service_line + flush_pkt + refs_data
        
        return {
            'content': body,
            'content_type': content_type,
            'headers': {
                'Cache-Control': 'no-cache',
                'Expires': 'Fri, 01 Jan 1980 00:00:00 GMT',
                'Pragma': 'no-cache'
            }
        }
    
    @classmethod
    def build_service_result(
        cls,
        service: GitService,
        result_data: bytes
    ) -> Dict[str, Any]:
        """Build service result response."""
        content_type = cls.SERVICE_CONTENT_TYPES[service]['result']
        
        return {
            'content': result_data,
            'content_type': content_type,
            'headers': {
                'Cache-Control': 'no-cache'
            }
        }
    
    @classmethod
    def build_error_response(
        cls,
        error_message: str,
        status_code: int = 500
    ) -> Dict[str, Any]:
        """Build error response in Git format."""
        # Git expects errors in pkt-line format
        error_line = cls._encode_pkt_line(f"ERR {error_message}\n")
        
        return {
            'content': error_line,
            'content_type': 'application/x-git-upload-pack-advertisement',
            'status_code': status_code,
            'headers': {
                'Cache-Control': 'no-cache'
            }
        }
    
    @classmethod
    def build_not_found_response(cls) -> Dict[str, Any]:
        """Build 404 response for Git."""
        return cls.build_error_response(
            "Repository not found",
            status_code=404
        )
    
    @classmethod
    def build_unauthorized_response(cls) -> Dict[str, Any]:
        """Build 401 response for Git."""
        return {
            'content': b"Unauthorized",
            'content_type': 'text/plain',
            'status_code': 401,
            'headers': {
                'WWW-Authenticate': 'Basic realm="Git2in"'
            }
        }
    
    @classmethod
    def _encode_pkt_line(cls, data: str) -> bytes:
        """Encode string in pkt-line format."""
        encoded = data.encode('utf-8')
        length = len(encoded) + 4
        
        if length > 65520:
            raise ValueError("Data too large for pkt-line")
        
        return f"{length:04x}".encode('ascii') + encoded