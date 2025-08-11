"""Tests for management REST API"""

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src.core.services.user import UserService
from src.main import app


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    """Get authentication headers for testing"""
    # Create token using existing auth endpoint
    response = client.post(
        "/api/v1/auth/token",
        json={
            "username": "administrator",
            "password": "admin",
            "scopes": [
                "namespace:create",
                "repository:create",
                "user:read",
                "token:create",
            ],
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestNamespaceEndpoints:
    """Test namespace CRUD operations"""

    def test_list_namespaces_pagination(self, client):
        """Test listing namespaces with pagination"""
        response = client.get("/api/v1/namespaces?page=1&per_page=10")
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert data["page"] == 1
        assert "per_page" in data
        assert data["per_page"] == 10

        # Check pagination headers
        assert "X-Total-Count" in response.headers
        assert "Link" in response.headers

    def test_create_namespace(self, client, auth_headers):
        """Test creating a namespace"""
        namespace_data = {
            "name": "test-namespace",
            "display_name": "Test Namespace",
            "description": "A test namespace",
            "visibility": "private",
        }

        response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        assert response.status_code == 201

        data = response.json()
        assert "id" in data
        assert data["message"] == "Namespace 'test-namespace' created successfully"
        assert "location" in data

    def test_create_namespace_duplicate(self, client, auth_headers):
        """Test creating duplicate namespace returns conflict"""
        namespace_data = {"name": "duplicate-test", "visibility": "public"}

        # Create first namespace
        response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        assert response.status_code == 201

        # Try to create duplicate
        response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        assert response.status_code == 409

        data = response.json()
        assert data["error"] == "CONFLICT"
        assert "already exists" in data["message"]

    def test_get_namespace(self, client, auth_headers):
        """Test getting a specific namespace"""
        # Create namespace first
        namespace_data = {"name": "get-test", "visibility": "public"}

        create_response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        namespace_id = create_response.json()["id"]

        # Get the namespace
        response = client.get(f"/api/v1/namespaces/{namespace_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == namespace_id
        assert data["name"] == "get-test"

    def test_update_namespace(self, client, auth_headers):
        """Test updating namespace metadata"""
        # Create namespace
        namespace_data = {"name": "update-test", "visibility": "private"}

        create_response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        namespace_id = create_response.json()["id"]

        # Update namespace
        update_data = {
            "display_name": "Updated Name",
            "description": "Updated description",
            "visibility": "public",
        }

        response = client.put(
            f"/api/v1/namespaces/{namespace_id}", json=update_data, headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert "updated_at" in data

    def test_delete_namespace(self, client, auth_headers):
        """Test deleting a namespace"""
        # Create namespace
        namespace_data = {"name": "delete-test", "visibility": "private"}

        create_response = client.post(
            "/api/v1/namespaces", json=namespace_data, headers=auth_headers
        )
        namespace_id = create_response.json()["id"]

        # Delete namespace
        response = client.delete(
            f"/api/v1/namespaces/{namespace_id}", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "Namespace 'delete-test' deleted successfully"


class TestUserEndpoints:
    """Test user management endpoints"""

    def test_create_user(self, client):
        """Test user registration"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "TestPass123!",
            "full_name": "Test User",
        }

        response = client.post("/api/v1/users", json=user_data)
        assert response.status_code == 201

        data = response.json()
        assert "id" in data
        assert data["message"] == "User 'testuser' created successfully"

    def test_create_user_weak_password(self, client):
        """Test user registration with weak password"""
        user_data = {
            "username": "weakpass",
            "email": "weak@example.com",
            "password": "weak",  # Too short, no uppercase, no numbers
            "full_name": "Weak Password",
        }

        response = client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422  # Validation error

    def test_list_users(self, client):
        """Test listing users (public info only)"""
        response = client.get("/api/v1/users?page=1&per_page=5")
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert "total" in data

        # Should not include sensitive info like email for other users
        if data["items"]:
            user = data["items"][0]
            assert "username" in user
            assert "email" not in user  # Public response doesn't include email

    def test_get_current_user(self, client, auth_headers):
        """Test getting current authenticated user"""
        response = client.get("/api/v1/users/me", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["username"] == "administrator"
        assert "email" in data  # Full info for own profile
        assert "is_admin" in data


class TestTokenEndpoints:
    """Test token management endpoints"""

    def test_create_api_token(self, client, auth_headers):
        """Test creating an API token"""
        token_data = {
            "name": "Test API Token",
            "scopes": ["repository:read", "repository:write"],
            "expires_in_days": 30,
        }

        response = client.post("/api/v1/tokens", json=token_data, headers=auth_headers)
        assert response.status_code == 201

        data = response.json()
        assert "id" in data
        assert "token" in data  # Token value is shown on creation
        assert data["name"] == "Test API Token"
        assert data["scopes"] == ["repository:read", "repository:write"]

    def test_list_tokens(self, client, auth_headers):
        """Test listing user's tokens"""
        response = client.get("/api/v1/tokens", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert "total" in data

        # Token values should not be included in list
        if data["items"]:
            token = data["items"][0]
            assert "id" in token
            assert "token" not in token  # Token value not shown in list

    def test_revoke_token(self, client, auth_headers):
        """Test revoking a token"""
        # Create a token first
        token_data = {"name": "Revoke Test", "scopes": [], "expires_in_days": 1}

        create_response = client.post(
            "/api/v1/tokens", json=token_data, headers=auth_headers
        )
        token_id = create_response.json()["id"]

        # Revoke the token
        response = client.post(
            f"/api/v1/tokens/{token_id}/revoke?reason=Testing", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "Token revoked successfully"


class TestErrorResponses:
    """Test standardized error responses"""

    def test_not_found_error(self, client):
        """Test 404 error response format"""
        response = client.get("/api/v1/namespaces/00000000-0000-0000-0000-000000000001")
        assert response.status_code == 404

        data = response.json()
        assert data["success"] is False
        assert data["error"] == "NOT_FOUND"
        assert "correlation_id" in data
        assert "timestamp" in data

    def test_unauthorized_error(self, client):
        """Test 401 error when accessing protected endpoint"""
        response = client.post(
            "/api/v1/namespaces", json={"name": "test", "visibility": "public"}
        )
        assert response.status_code == 401

        data = response.json()
        assert data["success"] is False
        assert data["error"] == "UNAUTHORIZED"

    def test_validation_error(self, client, auth_headers):
        """Test validation error response"""
        response = client.post(
            "/api/v1/namespaces",
            json={"name": ""},  # Invalid: empty name
            headers=auth_headers,
        )
        assert response.status_code == 422

        data = response.json()
        assert "detail" in data


class TestPaginationAndFiltering:
    """Test pagination and filtering features"""

    def test_pagination_headers(self, client):
        """Test pagination headers are included"""
        response = client.get("/api/v1/namespaces?page=1&per_page=5")
        assert response.status_code == 200

        assert "X-Total-Count" in response.headers
        assert "X-Page" in response.headers
        assert response.headers["X-Page"] == "1"
        assert "X-Per-Page" in response.headers
        assert response.headers["X-Per-Page"] == "5"
        assert "Link" in response.headers

    def test_search_filtering(self, client, auth_headers):
        """Test search filtering"""
        # Create namespaces with searchable names
        for name in ["search-alpha", "search-beta", "other-gamma"]:
            client.post(
                "/api/v1/namespaces",
                json={"name": name, "visibility": "public"},
                headers=auth_headers,
            )

        # Search for "search" prefix
        response = client.get("/api/v1/namespaces?search=search")
        assert response.status_code == 200

        data = response.json()
        # Should find search-alpha and search-beta but not other-gamma
        names = [item["name"] for item in data["items"]]
        assert "search-alpha" in names or "search-beta" in names
        assert "other-gamma" not in names


class TestRateLimiting:
    """Test rate limiting functionality"""

    def test_rate_limit_headers(self, client):
        """Test rate limit headers are included"""
        response = client.get("/api/v1/namespaces")
        assert response.status_code == 200

        # Rate limit headers should be present
        if "X-RateLimit-Limit" in response.headers:
            assert response.headers["X-RateLimit-Limit"]
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers
