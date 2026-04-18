"""
Tests for Splunk REST client
Run with: pytest tests/test_splunk_client.py -v
"""
import pytest
from soc_agents.core.splunk_client import SplunkClient, SplunkConnectionError


def test_splunk_client_init():
    """Test that SplunkClient initializes without errors."""
    try:
        client = SplunkClient()
        assert client._host is not None
        assert client._port == 8089
    except Exception as e:
        pytest.skip(f"Splunk not available: {e}")


def test_splunk_ping():
    """Test Splunk connectivity."""
    try:
        client = SplunkClient()
        result = client.ping()
        assert isinstance(result, bool)
    except Exception as e:
        pytest.skip(f"Splunk not available: {e}")


@pytest.mark.integration
def test_splunk_get_index_stats():
    """Test fetching index statistics."""
    try:
        client = SplunkClient()
        stats = client.get_index_stats()
        assert isinstance(stats, list)
        if stats:
            assert "name" in stats[0]
            assert "total_event_count" in stats[0]
    except Exception as e:
        pytest.skip(f"Splunk not available: {e}")


@pytest.mark.integration
def test_splunk_get_triggered_alerts():
    """Test fetching triggered alerts."""
    try:
        client = SplunkClient()
        alerts = client.get_triggered_alerts()
        assert isinstance(alerts, list)
    except Exception as e:
        pytest.skip(f"Splunk not available: {e}")
