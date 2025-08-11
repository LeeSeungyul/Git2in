"""API client for Git2in CLI."""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from rich.console import Console

console = Console()


class APIError(Exception):
    """API error exception."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        details: Optional[Dict] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class APIClient:
    """HTTP client for Git2in API."""

    def __init__(
        self, base_url: str, auth_token: Optional[str] = None, debug: bool = False
    ):
        """
        Initialize API client.

        Args:
            base_url: Base URL for API
            auth_token: Optional authentication token
            debug: Enable debug output
        """
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.debug = debug

        # Configure headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

        # Create HTTP client
        self.client = httpx.Client(
            base_url=self.base_url,
            headers=self.headers,
            timeout=30.0,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close HTTP client."""
        self.client.close()

    def _log_debug(self, message: str):
        """Log debug message if debug mode is enabled."""
        if self.debug:
            console.print(f"[dim]DEBUG: {message}[/dim]")

    def _handle_response(self, response: httpx.Response) -> Any:
        """
        Handle API response.

        Args:
            response: HTTP response

        Returns:
            Response data

        Raises:
            APIError: If request failed
        """
        self._log_debug(f"Response status: {response.status_code}")

        if response.status_code == 204:
            return None

        try:
            data = response.json() if response.content else None
        except json.JSONDecodeError:
            data = None

        if response.is_error:
            error_message = "API request failed"

            if data and isinstance(data, dict):
                error_message = data.get("detail", data.get("message", error_message))

            raise APIError(
                message=error_message, status_code=response.status_code, details=data
            )

        return data

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """
        Make API request.

        Args:
            method: HTTP method
            path: API path
            params: Query parameters
            json_data: JSON request body
            **kwargs: Additional request arguments

        Returns:
            Response data
        """
        url = urljoin(self.base_url + "/", path.lstrip("/"))

        self._log_debug(f"{method} {url}")
        if params:
            self._log_debug(f"Params: {params}")
        if json_data:
            self._log_debug(f"Body: {json_data}")

        response = self.client.request(
            method=method, url=url, params=params, json=json_data, **kwargs
        )

        return self._handle_response(response)

    def get(self, path: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> Any:
        """Make GET request."""
        return self.request("GET", path, params=params, **kwargs)

    def post(
        self, path: str, json_data: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Any:
        """Make POST request."""
        return self.request("POST", path, json_data=json_data, **kwargs)

    def put(
        self, path: str, json_data: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Any:
        """Make PUT request."""
        return self.request("PUT", path, json_data=json_data, **kwargs)

    def patch(
        self, path: str, json_data: Optional[Dict[str, Any]] = None, **kwargs
    ) -> Any:
        """Make PATCH request."""
        return self.request("PATCH", path, json_data=json_data, **kwargs)

    def delete(self, path: str, **kwargs) -> Any:
        """Make DELETE request."""
        return self.request("DELETE", path, **kwargs)

    # Namespace operations
    def list_namespaces(
        self, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List namespaces."""
        response = self.get(
            "/api/v1/namespaces", params={"limit": limit, "offset": offset}
        )
        return response.get("items", []) if response else []

    def get_namespace(self, name: str) -> Dict[str, Any]:
        """Get namespace details."""
        return self.get(f"/api/v1/namespaces/{name}")

    def create_namespace(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create namespace."""
        return self.post("/api/v1/namespaces", json_data=data)

    def delete_namespace(self, name: str):
        """Delete namespace."""
        return self.delete(f"/api/v1/namespaces/{name}")

    # Repository operations
    def list_repositories(
        self, namespace: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List repositories."""
        params = {"limit": limit, "offset": offset}
        if namespace:
            params["namespace"] = namespace
        response = self.get("/api/v1/repositories", params=params)
        return response.get("items", []) if response else []

    def get_repository(self, namespace: str, name: str) -> Dict[str, Any]:
        """Get repository details."""
        return self.get(f"/api/v1/repositories/{namespace}/{name}")

    def create_repository(self, namespace: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create repository."""
        return self.post(f"/api/v1/repositories/{namespace}", json_data=data)

    def delete_repository(self, namespace: str, name: str):
        """Delete repository."""
        return self.delete(f"/api/v1/repositories/{namespace}/{name}")

    # User operations
    def list_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List users."""
        response = self.get("/api/v1/users", params={"limit": limit, "offset": offset})
        return response.get("items", []) if response else []

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get user details."""
        return self.get(f"/api/v1/users/{user_id}")

    def create_user(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create user."""
        return self.post("/api/v1/users", json_data=data)

    def update_user(self, user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user."""
        return self.patch(f"/api/v1/users/{user_id}", json_data=data)

    def delete_user(self, user_id: str):
        """Delete user."""
        return self.delete(f"/api/v1/users/{user_id}")

    # Token operations
    def list_tokens(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List tokens."""
        response = self.get("/api/v1/tokens", params={"limit": limit, "offset": offset})
        return response.get("items", []) if response else []

    def create_token(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create token."""
        return self.post("/api/v1/tokens", json_data=data)

    def revoke_token(self, token_id: str):
        """Revoke token."""
        return self.delete(f"/api/v1/tokens/{token_id}")

    def validate_token(self) -> Dict[str, Any]:
        """Validate current token."""
        return self.get("/api/v1/tokens/validate")
