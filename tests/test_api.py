"""
Tests for the FastAPI integration.
"""

from __future__ import annotations
from tests.export_requests import log_request



import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.config import DetectionConfig, RateLimitConfig


@pytest.fixture
def client():
    """Create a test client with strict rate limiting."""
    config = DetectionConfig(
        rate_limit=RateLimitConfig(
            max_requests=5,
            window_seconds=60,
        ),
    )
    app = create_app(config=config, log_level="WARNING")
    return TestClient(app)


class TestDetectionAPI:
    """Tests for the detection API endpoints."""
    
    def test_health_check(self, client: TestClient):
        """Should return healthy status."""
        response = client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "components" in data
    
    def test_detect_legit_request(self, client: TestClient):
        """Should ALLOW legitimate requests."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "GET",
                "url": "/api/users?page=1",
                "headers": {"content-type": "application/json"},
                "body": "",
                "ip_address": "192.168.1.100",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_threat"] is False
        assert data["threat_level"] == "SAFE"
        assert data["recommendation"] == "ALLOW"
    
    def test_detect_sqli(self, client: TestClient):
        """Should BLOCK SQL injection."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "POST",
                "url": "/api/login",
                "headers": {},
                "body": "{'user': 'admin' OR 1=1 --}",
                "ip_address": "10.0.0.1",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_threat"] is True
        assert data["recommendation"] == "BLOCK"
        assert len(data["matched_rules"]) > 0
    
    def test_detect_xss(self, client: TestClient):
        """Should BLOCK XSS."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "POST",
                "url": "/api/comments",
                "headers": {},
                "body": '{"text": "<script>alert(1)</script>"}',
                "ip_address": "10.0.0.2",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_threat"] is True
        assert data["recommendation"] == "BLOCK"
    
    def test_detect_path_traversal(self, client: TestClient):
        """Should BLOCK path traversal."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "GET",
                "url": "/api/files?path=../../../etc/passwd",
                "headers": {},
                "body": "",
                "ip_address": "10.0.0.3",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_threat"] is True
        assert data["recommendation"] == "BLOCK"
    
    def test_rate_limit_enforcement(self, client: TestClient):
        """Should enforce rate limits."""
        request_data = {
            "method": "GET",
            "url": "/api/test",
            "headers": {},
            "body": "",
            "ip_address": "10.10.10.10",
        }
        
        # Make 5 requests (limit)
        for _ in range(5):
            response = client.post("/api/v1/detect", json=request_data)
            assert response.status_code == 200
            assert response.json()["recommendation"] == "ALLOW"
        
        # 6th request should be blocked
        response = client.post("/api/v1/detect", json=request_data)
        assert response.status_code == 200
        assert response.json()["recommendation"] == "BLOCK"
        assert response.json()["triggering_factor"] == "rate_limit"
    
    def test_invalid_method(self, client: TestClient):
        """Should reject invalid HTTP methods."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "INVALID",
                "url": "/api/test",
                "headers": {},
                "body": "",
                "ip_address": "192.168.1.1",
            },
        )
        
        assert response.status_code == 422
    
    def test_missing_required_fields(self, client: TestClient):
        """Should reject requests with missing required fields."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "GET",
                # Missing url and ip_address
            },
        )
        
        assert response.status_code == 422
    
    def test_invalid_ip_address(self, client: TestClient):
        """Should reject invalid IP addresses."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "GET",
                "url": "/api/test",
                "headers": {},
                "body": "",
                "ip_address": "not-an-ip",
            },
        )
        
        assert response.status_code == 422
    
    def test_response_structure(self, client: TestClient):
        """Should return properly structured response."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "GET",
                "url": "/api/test",
                "headers": {},
                "body": "",
                "ip_address": "192.168.1.1",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify all required fields
        assert "is_threat" in data
        assert "threat_level" in data
        assert "recommendation" in data
        assert "matched_rules" in data
        assert "rate_limit_status" in data
        assert "anomaly_scores" in data
        assert "features" in data
        assert "reason" in data
        assert "triggering_factor" in data
        
        # Verify nested structure
        assert "allowed" in data["rate_limit_status"]
        assert "scores" in data["anomaly_scores"]
        assert "anomaly_count" in data["anomaly_scores"]
    
    def test_case_insensitive_method(self, client: TestClient):
        """Should normalize HTTP method to uppercase."""
        response = client.post(
            "/api/v1/detect",
            json={
                "method": "get",  # lowercase
                "url": "/api/test",
                "headers": {},
                "body": "",
                "ip_address": "192.168.1.1",
            },
        )
        
        assert response.status_code == 200

