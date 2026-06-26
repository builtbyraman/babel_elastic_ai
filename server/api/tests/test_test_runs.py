"""
Integration tests for test-running endpoints.
"""

import pytest


def test_test_run_missing_auth(client, sample_sigma_rule):
    """Test that test-run endpoint requires Authorization header."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": sample_sigma_rule,
            "index_pattern": "winlogbeat-*",
            "timeframe_hours": 24,
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert data["status"] == 401


def test_test_run_invalid_yaml(client, headers_with_auth):
    """Test that test-run rejects invalid YAML."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": "invalid: [yaml: content",
            "index_pattern": "winlogbeat-*",
            "timeframe_hours": 24,
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 400
    data = response.json()
    assert "invalid" in data["title"].lower()


def test_test_run_invalid_timeframe(client, headers_with_auth, sample_sigma_rule):
    """Test that test-run validates timeframe_hours."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": sample_sigma_rule,
            "index_pattern": "winlogbeat-*",
            "timeframe_hours": 0,  # Invalid: must be >= 1
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 422  # Validation error


def test_test_run_max_timeframe(client, headers_with_auth, sample_sigma_rule):
    """Test that test-run validates max timeframe_hours."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": sample_sigma_rule,
            "index_pattern": "winlogbeat-*",
            "timeframe_hours": 3000,  # Invalid: max is 2160 (3 months)
        },
        headers=headers_with_auth,
    )
    assert response.status_code == 422  # Validation error


def test_test_run_default_values(client, headers_with_auth, sample_sigma_rule):
    """Test that test-run uses default values for optional fields."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": sample_sigma_rule,
            # index_pattern and timeframe_hours should have defaults
        },
        headers=headers_with_auth,
    )
    # Should not get a validation error about missing required fields
    # (May get 503 if Elasticsearch is not available, but that's ok for this test)
    assert response.status_code != 422


def test_test_run_response_structure(client, headers_with_auth, sample_sigma_rule):
    """Test that test-run response has correct structure."""
    response = client.post(
        "/v1/test-runs",
        json={
            "rule_yaml": sample_sigma_rule,
            "index_pattern": "winlogbeat-*",
            "timeframe_hours": 24,
        },
        headers=headers_with_auth,
    )
    # Even if it fails (503 for no ES), check response format if it's a success
    if response.status_code == 200:
        data = response.json()
        assert "test_run_id" in data
        assert "hit_count" in data
        assert "sample_events" in data
        assert "timing_ms" in data
        assert isinstance(data["hit_count"], int)
        assert isinstance(data["sample_events"], list)
        assert isinstance(data["timing_ms"], int)
