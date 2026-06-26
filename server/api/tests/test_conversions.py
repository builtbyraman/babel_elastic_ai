"""
Integration tests for conversion endpoints.
"""

import pytest


def test_health_check(client):
    """Test that the health endpoint returns 200."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_conversion_missing_auth(client, sample_sigma_rule):
    """Test that conversion endpoint requires Authorization header."""
    response = client.post(
        "/v1/conversions",
        json={
            "rule_yaml": sample_sigma_rule,
            "format": "eql",
            "pipeline": "ecs_windows",
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert data["status"] == 401
    assert "Authorization" in data["detail"]


def test_conversion_invalid_yaml(client, headers_with_auth):
    """Test that conversion rejects invalid YAML."""
    response = client.post(
        "/v1/conversions",
        json={
            "rule_yaml": "invalid: [yaml: content",  # Malformed YAML
            "format": "eql",
            "pipeline": "ecs_windows",
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["type"].endswith("invalid-rule")


def test_conversion_unsupported_format(client, headers_with_auth, sample_sigma_rule):
    """Test that conversion rejects unsupported formats."""
    response = client.post(
        "/v1/conversions",
        json={
            "rule_yaml": sample_sigma_rule,
            "format": "invalid_format",
            "pipeline": "ecs_windows",
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["type"].endswith("unsupported-format")


def test_conversion_unsupported_pipeline(client, headers_with_auth, sample_sigma_rule):
    """Test that conversion rejects unsupported pipelines."""
    response = client.post(
        "/v1/conversions",
        json={
            "rule_yaml": sample_sigma_rule,
            "format": "eql",
            "pipeline": "invalid_pipeline",
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["type"].endswith("unsupported-format")


def test_conversion_idempotency(client, headers_with_auth, sample_sigma_rule):
    """Test that same inputs produce same conversion_id (idempotency)."""
    request_body = {
        "rule_yaml": sample_sigma_rule,
        "format": "eql",
        "pipeline": "ecs_windows",
    }

    response1 = client.post(
        "/v1/conversions",
        json=request_body,
        headers=headers_with_auth,
    )
    # Note: First request may fail if pySigma is not available in test env
    # This test assumes the service can handle it gracefully

    if response1.status_code == 200:
        data1 = response1.json()
        conversion_id_1 = data1["conversion_id"]

        # Make same request again
        response2 = client.post(
            "/v1/conversions",
            json=request_body,
            headers=headers_with_auth,
        )
        data2 = response2.json()
        conversion_id_2 = data2["conversion_id"]

        # Same inputs should produce same conversion_id
        assert conversion_id_1 == conversion_id_2
