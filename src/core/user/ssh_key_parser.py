"""SSH key parsing module - handles SSH public key parsing only"""

import base64
import hashlib
import re
from typing import Optional, Tuple

from src.core.user.user_types import SSHKeyInfo


class SSHKeyParser:
    """Handles SSH public key parsing only"""
    
    # Supported key types
    SUPPORTED_KEY_TYPES = {
        'ssh-rsa': 2048,  # Minimum bits for RSA
        'ssh-ed25519': 256,
        'ecdsa-sha2-nistp256': 256,
        'ecdsa-sha2-nistp384': 384,
        'ecdsa-sha2-nistp521': 521,
    }
    
    SSH_KEY_PATTERN = re.compile(
        r'^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+([A-Za-z0-9+/]+={0,2})\s*(.*)$'
    )
    
    def parse_public_key(self, key_string: str) -> Optional[SSHKeyInfo]:
        """
        Parse an SSH public key string
        
        Args:
            key_string: The SSH public key string
            
        Returns:
            SSHKeyInfo if valid, None otherwise
        """
        if not key_string:
            return None
        
        # Strip whitespace
        key_string = key_string.strip()
        
        # Match key format
        match = self.SSH_KEY_PATTERN.match(key_string)
        if not match:
            return None
        
        key_type = match.group(1)
        key_data = match.group(2)
        comment = match.group(3).strip() or None
        
        # Validate key type
        if key_type not in self.SUPPORTED_KEY_TYPES:
            return None
        
        # Validate base64 encoding
        try:
            decoded = base64.b64decode(key_data)
        except Exception:
            return None
        
        # Calculate fingerprint
        fingerprint = self._calculate_fingerprint(decoded)
        
        return SSHKeyInfo(
            key_type=key_type,
            key_data=key_data,
            comment=comment,
            fingerprint=fingerprint
        )
    
    def _calculate_fingerprint(self, key_bytes: bytes) -> str:
        """
        Calculate SSH key fingerprint (SHA256 base64)
        
        Args:
            key_bytes: The decoded key bytes
            
        Returns:
            The fingerprint string
        """
        digest = hashlib.sha256(key_bytes).digest()
        b64_digest = base64.b64encode(digest).decode('ascii')
        # Remove trailing '=' padding
        return f"SHA256:{b64_digest.rstrip('=')}"
    
    def format_fingerprint(self, fingerprint: str) -> str:
        """
        Format fingerprint for display
        
        Args:
            fingerprint: The raw fingerprint
            
        Returns:
            Formatted fingerprint
        """
        # Add colons for readability (like OpenSSH)
        if fingerprint.startswith("SHA256:"):
            return fingerprint
        return fingerprint