"""Authentication middleware for ShadowGate Proxy."""

import base64
import logging
import hashlib
from typing import Optional

from shadowgate.config import Config

logger = logging.getLogger("shadowgate.proxy.auth")


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 for simplicity (bcrypt recommended for prod)."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    if len(hashed_password) != 64:
        # Stored as plain text — direct comparison
        return plain_password == hashed_password
    return hash_password(plain_password) == hashed_password


class ProxyAuthenticator:
    """Handles authentication for the proxy server."""

    def __init__(self, config: Config):
        self.config = config

        # Build user lookup: {username: password}
        raw_users = self.config.get("proxy", "auth", "users", default=[]) or []
        self.users: dict[str, str] = {}
        for entry in raw_users:
            if isinstance(entry, dict):
                self.users[entry["username"]] = entry.get("password", "")
            elif isinstance(entry, str):
                self.users[entry] = ""

        # Build API key set for O(1) lookup
        raw_keys = self.config.get("proxy", "auth", "api_keys", default=[]) or []
        self.api_keys: set[str] = set(raw_keys)

    def authenticate(self, request) -> Optional[str]:
        """Authenticate a request. Returns username if successful, None otherwise."""
        client_ip = request.remote

        # Check API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            username = self._check_api_key(api_key)
            if username:
                logger.info(f"API Key auth success for {username} from {client_ip}")
                return username

        # Check Basic Auth
        auth_header = request.headers.get("Proxy-Authorization")
        if auth_header:
            username = self._check_basic_auth(auth_header)
            if username:
                logger.info(f"Basic auth success for {username} from {client_ip}")
                return username

        logger.warning(f"Auth failed from {client_ip}")
        return None

    def _check_basic_auth(self, auth_header: str) -> Optional[str]:
        """Check Proxy-Authorization header."""
        try:
            auth_type, encoded_credentials = auth_header.split(" ", 1)
            if auth_type.lower() != "basic":
                return None

            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)

            stored_password = self.users.get(username)
            if stored_password is not None and verify_password(password, stored_password):
                return username
        except Exception as e:
            logger.debug(f"Error parsing basic auth: {e}")

        return None

    def _check_api_key(self, api_key: str) -> Optional[str]:
        """Check X-API-Key header. Returns 'api-user' if key is valid."""
        if api_key in self.api_keys:
            return "api-user"
        return None
