"""HMAC-SHA256 signing and key management"""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

from src.core.config import settings
from src.core.exceptions import AuthenticationError, InternalServerError
from src.infrastructure.logging import get_logger

logger = get_logger(__name__)


class SigningKey:
    """Represents a signing key with metadata"""

    def __init__(
        self,
        key_id: str,
        key_bytes: bytes,
        created_at: datetime,
        expires_at: Optional[datetime] = None,
        is_active: bool = True,
    ):
        self.key_id = key_id
        self.key_bytes = key_bytes
        self.created_at = created_at
        self.expires_at = expires_at
        self.is_active = is_active

    def is_valid(self) -> bool:
        """Check if key is still valid"""
        if not self.is_active:
            return False
        if self.expires_at and datetime.utcnow() >= self.expires_at:
            return False
        return True

    def sign(self, message: str) -> str:
        """Sign a message with this key"""
        signature = hmac.new(
            self.key_bytes, message.encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    def verify(self, message: str, signature: str) -> bool:
        """Verify a signature with this key"""
        try:
            # Add padding if needed
            signature_padded = signature + "=" * (4 - len(signature) % 4)
            signature_bytes = base64.urlsafe_b64decode(signature_padded)

            expected_signature = hmac.new(
                self.key_bytes, message.encode("utf-8"), hashlib.sha256
            ).digest()

            return hmac.compare_digest(signature_bytes, expected_signature)
        except Exception as e:
            logger.warning("signature_verification_error", error=str(e))
            return False


class KeyManager:
    """Manages signing keys with rotation support"""

    def __init__(
        self, key_rotation_days: int = 30, key_overlap_days: int = 7, max_keys: int = 5
    ):
        self.key_rotation_days = key_rotation_days
        self.key_overlap_days = key_overlap_days
        self.max_keys = max_keys

        self._keys: Dict[str, SigningKey] = {}
        self._active_key_id: Optional[str] = None
        self._lock = Lock()

        # Initialize with default key
        self._initialize_keys()

    def _initialize_keys(self) -> None:
        """Initialize keys from environment or generate new ones"""
        # Try to load from environment
        if hasattr(settings, "signing_key") and settings.signing_key:
            key_bytes = base64.b64decode(settings.signing_key)
            key = SigningKey(
                key_id="default",
                key_bytes=key_bytes,
                created_at=datetime.utcnow(),
                expires_at=None,  # Default key doesn't expire
                is_active=True,
            )
            self._keys["default"] = key
            self._active_key_id = "default"
            logger.info("key_manager_initialized", source="environment")
        else:
            # Generate new key
            self.rotate_key()
            logger.info("key_manager_initialized", source="generated")

    def generate_key(self) -> SigningKey:
        """Generate a new signing key"""
        key_bytes = secrets.token_bytes(32)  # 256-bit key
        key_id = secrets.token_urlsafe(16)

        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(
            days=self.key_rotation_days + self.key_overlap_days
        )

        return SigningKey(
            key_id=key_id,
            key_bytes=key_bytes,
            created_at=created_at,
            expires_at=expires_at,
            is_active=True,
        )

    def rotate_key(self) -> SigningKey:
        """Rotate to a new signing key"""
        with self._lock:
            # Generate new key
            new_key = self.generate_key()

            # Deactivate old active key (but keep for verification)
            if self._active_key_id and self._active_key_id in self._keys:
                old_key = self._keys[self._active_key_id]
                old_key.is_active = False

                # Set expiration for grace period
                old_key.expires_at = datetime.utcnow() + timedelta(
                    days=self.key_overlap_days
                )

            # Add new key
            self._keys[new_key.key_id] = new_key
            self._active_key_id = new_key.key_id

            # Clean up old expired keys
            self._cleanup_expired_keys()

            logger.info(
                "key_rotated", new_key_id=new_key.key_id, total_keys=len(self._keys)
            )

            return new_key

    def _cleanup_expired_keys(self) -> None:
        """Remove expired keys, keeping at most max_keys"""
        # Remove expired keys
        expired_keys = [
            key_id
            for key_id, key in self._keys.items()
            if not key.is_valid() and key_id != self._active_key_id
        ]

        for key_id in expired_keys:
            del self._keys[key_id]
            logger.debug("expired_key_removed", key_id=key_id)

        # If still too many keys, remove oldest inactive ones
        if len(self._keys) > self.max_keys:
            inactive_keys = [
                (key.created_at, key_id)
                for key_id, key in self._keys.items()
                if key_id != self._active_key_id
            ]
            inactive_keys.sort()  # Sort by creation time

            # Remove oldest keys
            keys_to_remove = len(self._keys) - self.max_keys
            for _, key_id in inactive_keys[:keys_to_remove]:
                del self._keys[key_id]
                logger.debug("old_key_removed", key_id=key_id)

    def get_active_key(self) -> SigningKey:
        """Get the current active signing key"""
        with self._lock:
            if not self._active_key_id or self._active_key_id not in self._keys:
                raise InternalServerError("No active signing key available")

            key = self._keys[self._active_key_id]
            if not key.is_valid():
                # Active key expired, rotate
                key = self.rotate_key()

            return key

    def get_key(self, key_id: str) -> Optional[SigningKey]:
        """Get a specific key by ID"""
        with self._lock:
            return self._keys.get(key_id)

    def get_valid_keys(self) -> List[SigningKey]:
        """Get all valid keys for verification"""
        with self._lock:
            return [key for key in self._keys.values() if key.is_valid()]

    def sign(self, message: str) -> Tuple[str, str]:
        """Sign a message with the active key, return (signature, key_id)"""
        key = self.get_active_key()
        signature = key.sign(message)
        return signature, key.key_id

    def verify(
        self, message: str, signature: str, key_id: Optional[str] = None
    ) -> bool:
        """Verify a signature, optionally with a specific key"""
        if key_id:
            # Try specific key
            key = self.get_key(key_id)
            if key and key.is_valid():
                return key.verify(message, signature)
            return False
        else:
            # Try all valid keys
            for key in self.get_valid_keys():
                if key.verify(message, signature):
                    return True
            return False

    def export_public_keys(self) -> Dict[str, Dict]:
        """Export public key information (for JWKS endpoint)"""
        with self._lock:
            keys = {}
            for key_id, key in self._keys.items():
                if key.is_valid():
                    keys[key_id] = {
                        "kid": key_id,
                        "alg": "HS256",
                        "use": "sig",
                        "created_at": key.created_at.isoformat(),
                        "expires_at": (
                            key.expires_at.isoformat() if key.expires_at else None
                        ),
                        "is_active": key.is_active,
                    }
            return keys


class TokenSigner:
    """High-level token signing interface"""

    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.key_manager = key_manager or KeyManager()

    def sign_token(self, header: Dict, payload: Dict) -> str:
        """Sign a token and return the complete JWT-like token string"""
        # Encode header and payload
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

        payload_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )

        # Create message to sign
        message = f"{header_b64}.{payload_b64}"

        # Sign with active key
        signature, key_id = self.key_manager.sign(message)

        # Add key ID to header if not present
        if "kid" not in header:
            header["kid"] = key_id
            # Re-encode header with key ID
            header_b64 = (
                base64.urlsafe_b64encode(
                    json.dumps(header, separators=(",", ":")).encode()
                )
                .rstrip(b"=")
                .decode()
            )
            message = f"{header_b64}.{payload_b64}"
            signature, _ = self.key_manager.sign(message)

        # Return complete token
        return f"{message}.{signature}"

    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict], Optional[Dict]]:
        """
        Verify a token and return (is_valid, header, payload)
        """
        try:
            # Split token
            parts = token.split(".")
            if len(parts) != 3:
                return False, None, None

            header_b64, payload_b64, signature = parts

            # Decode header to get key ID
            header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            key_id = header.get("kid")

            if self.key_manager.verify(message, signature, key_id):
                return True, header, payload
            else:
                return False, None, None

        except Exception as e:
            logger.warning("token_verification_error", error=str(e))
            return False, None, None

    def rotate_key(self) -> None:
        """Trigger key rotation"""
        self.key_manager.rotate_key()


# Global token signer instance
token_signer = TokenSigner()
