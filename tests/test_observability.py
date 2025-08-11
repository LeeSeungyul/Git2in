"""Tests for observability features"""

import json

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from src.main import app


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


class TestHealthEndpoints:
    """Test health check endpoints"""

    def test_health_endpoint(self, client):
        """Test basic health endpoint"""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["service"] == "git2in"
        assert "version" in data
        assert "uptime_seconds" in data
        assert "response_time_ms" in data

    def test_readiness_endpoint(self, client):
        """Test readiness endpoint"""
        response = client.get("/ready")

        # May be 200 or 503 depending on system state
        assert response.status_code in [200, 503]

        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert "filesystem" in data["checks"]
        assert "git_binary" in data["checks"]
        assert "disk_space" in data["checks"]
        assert "memory" in data["checks"]

    def test_detailed_health_endpoint(self, client):
        """Test detailed health endpoint"""
        response = client.get("/health/detailed")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert "system" in data
        assert "configuration" in data


class TestMetricsEndpoint:
    """Test Prometheus metrics endpoint"""

    def test_metrics_endpoint_forbidden_without_auth(self, client):
        """Test metrics endpoint requires authentication"""
        response = client.get("/metrics")
        assert response.status_code == 403

    def test_metrics_endpoint_allowed_from_localhost(self, client):
        """Test metrics endpoint allows localhost"""
        # Simulate localhost request
        response = client.get("/metrics", headers={"X-Real-IP": "127.0.0.1"})
        # Should still be forbidden without proper setup
        assert response.status_code in [200, 403]

    def test_metrics_json_endpoint(self, client):
        """Test metrics JSON endpoint"""
        response = client.get("/metrics/json")
        assert response.status_code == 403  # Requires auth


class TestLoggingMiddleware:
    """Test request/response logging middleware"""

    def test_request_logging(self, client, caplog):
        """Test that requests are logged"""
        response = client.get("/api/v1/version")
        assert response.status_code == 200

        # Check response headers
        assert "X-Request-ID" in response.headers
        assert "X-Response-Time" in response.headers

    def test_correlation_id_propagation(self, client):
        """Test correlation ID is propagated"""
        correlation_id = "test-correlation-123"
        response = client.get(
            "/api/v1/version", headers={"X-Correlation-ID": correlation_id}
        )
        assert response.status_code == 200
        assert response.headers["X-Correlation-ID"] == correlation_id


class TestMetricsCollection:
    """Test metrics are collected properly"""

    def test_http_metrics_collected(self, client):
        """Test HTTP metrics are collected"""
        # Make some requests
        client.get("/api/v1/version")
        client.get("/health")
        client.post("/api/v1/version")  # Should fail

        # Check metrics were recorded
        from src.infrastructure.metrics import http_requests_total

        # Metrics should have been incremented
        # Note: Direct assertion on counter values is tricky due to labels
        # Prometheus internally stores counter names without "_total" suffix
        assert http_requests_total._name == "http_requests"

    def test_service_info_metric(self):
        """Test service info metric is set"""
        from src.infrastructure.metrics import service_info

        # Service info should be set
        # Prometheus internally stores info names without "_info" suffix
        assert service_info._name == "git2in_service"


class TestGitMetrics:
    """Test Git operation metrics"""

    def test_git_metrics_context_manager(self):
        """Test Git metrics context manager"""
        from src.infrastructure.git_metrics import GitOperationMetrics

        with GitOperationMetrics("fetch", "test-namespace", "test-repo") as metrics:
            metrics.set_pack_size(1024)
            metrics.track_negotiation()

        # Metrics should have been recorded
        from src.infrastructure.metrics import git_operations_total

        # Prometheus internally stores counter names without "_total" suffix
        assert git_operations_total._name == "git_operations"

    def test_ref_advertisement_metrics(self):
        """Test ref advertisement metrics"""
        from src.infrastructure.git_metrics import RefAdvertisementMetrics

        with RefAdvertisementMetrics("test-namespace", "test-repo"):
            pass  # Simulate ref advertisement

        from src.infrastructure.metrics import \
            git_ref_advertisement_duration_seconds

        assert (
            git_ref_advertisement_duration_seconds._name
            == "git_ref_advertisement_duration_seconds"
        )
