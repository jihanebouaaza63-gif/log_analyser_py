"""Unit tests for IP validation, IPinfo lookups, caching, and event enrichment."""

from copy import deepcopy
from unittest.mock import Mock, patch

import pytest
import requests

import process.geolocation as geolocation


@pytest.fixture(autouse=True)
def clear_location_cache(monkeypatch):
    """Keep every test independent of earlier IPinfo lookups."""
    geolocation._LOCATION_CACHE.clear()
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    yield
    geolocation._LOCATION_CACHE.clear()


def make_response(payload):
    response = Mock()
    response.json.return_value = payload
    return response


def test_private_ip_is_rejected_without_http_call():
    with patch.object(geolocation.requests, "get") as http_get:
        assert geolocation.get_location("192.168.1.10") is None

    http_get.assert_not_called()


def test_public_ip_request_uses_explicit_timeout():
    response = make_response({"city": "Mountain View", "country": "US"})

    with patch.object(geolocation.requests, "get", return_value=response) as http_get:
        result = geolocation.get_location("8.8.8.8")

    assert result is not None
    http_get.assert_called_once_with(
        "https://ipinfo.io/8.8.8.8/json/",
        timeout=5,
    )


def test_valid_ipinfo_response_returns_normalized_fields():
    payload = {
        "hostname": "dns.google",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "loc": "37.4056,-122.0775",
        "org": "AS15169 Google LLC",
        "postal": "94043",
        "timezone": "America/Los_Angeles",
    }

    with patch.object(geolocation.requests, "get", return_value=make_response(payload)):
        result = geolocation.get_location("8.8.8.8")

    assert result == {
        "ip": "8.8.8.8",
        "hostname": "dns.google",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "location": "37.4056,-122.0775",
        "organization": "AS15169 Google LLC",
        "postal": "94043",
        "timezone": "America/Los_Angeles",
    }


def test_second_lookup_for_same_ip_uses_cache():
    response = make_response({"city": "Mountain View", "country": "US"})

    with patch.object(geolocation.requests, "get", return_value=response) as http_get:
        first = geolocation.get_location("8.8.8.8")
        second = geolocation.get_location("8.8.8.8")

    assert first == second
    assert first is not second
    http_get.assert_called_once()


def test_http_error_returns_none():
    response = Mock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("503 Service Unavailable")

    with patch.object(geolocation.requests, "get", return_value=response):
        assert geolocation.get_location("8.8.8.8") is None


def test_network_error_returns_none():
    with patch.object(
        geolocation.requests,
        "get",
        side_effect=requests.exceptions.ConnectionError("connection failed"),
    ):
        assert geolocation.get_location("8.8.8.8") is None


def test_invalid_json_returns_none():
    response = Mock()
    response.json.side_effect = ValueError("invalid JSON")

    with patch.object(geolocation.requests, "get", return_value=response):
        assert geolocation.get_location("8.8.8.8") is None


def test_non_dictionary_json_response_returns_none():
    with patch.object(geolocation.requests, "get", return_value=make_response(["unexpected"])):
        assert geolocation.get_location("8.8.8.8") is None


def test_enrich_events_keeps_events_without_source_ip():
    events = [{"id": 1, "username": "alice"}, {"id": 2, "source_ip": None}]

    with patch.object(geolocation.requests, "get") as http_get:
        result = geolocation.enrich_events(events)

    assert len(result) == len(events)
    assert [event["id"] for event in result] == [1, 2]
    assert all(event["geolocation"] is None for event in result)
    http_get.assert_not_called()


def test_enrich_events_adds_geolocation_for_public_source_ip():
    payload = {"city": "Mountain View", "region": "California", "country": "US"}
    events = [{"id": 1, "source_ip": "8.8.8.8"}]

    with patch.object(geolocation.requests, "get", return_value=make_response(payload)) as http_get:
        result = geolocation.enrich_events(events)

    assert result[0]["geolocation"]["ip"] == "8.8.8.8"
    assert result[0]["geolocation"]["city"] == "Mountain View"
    http_get.assert_called_once_with(
        "https://ipinfo.io/8.8.8.8/json/",
        timeout=5,
    )


def test_enrich_events_keeps_event_when_geolocation_fails():
    events = [{"id": 1, "source_ip": "8.8.8.8"}]

    with patch.object(
        geolocation.requests,
        "get",
        side_effect=requests.exceptions.Timeout("timed out"),
    ):
        result = geolocation.enrich_events(events)

    assert len(result) == 1
    assert result[0]["id"] == 1
    assert result[0]["source_ip"] == "8.8.8.8"
    assert result[0]["geolocation"] is None


def test_enrich_events_does_not_modify_original_events():
    events = [{"id": 1, "source_ip": "8.8.8.8", "metadata": {"tag": "original"}}]
    original_snapshot = deepcopy(events)

    with patch.object(
        geolocation.requests,
        "get",
        return_value=make_response({"city": "Mountain View", "country": "US"}),
    ):
        result = geolocation.enrich_events(events)

    assert events == original_snapshot
    assert "geolocation" not in events[0]
    assert result[0] is not events[0]
    assert result[0]["geolocation"]["city"] == "Mountain View"


def test_token_comes_from_environment_and_is_sent_only_as_bearer_header(monkeypatch):
    token = "ipinfo-test-secret-not-real"
    monkeypatch.setenv("IPINFO_TOKEN", token)

    with patch.object(
        geolocation.requests,
        "get",
        return_value=make_response({"country": "US"}),
    ) as http_get:
        assert geolocation.get_location("8.8.8.8") is not None

    http_get.assert_called_once_with(
        "https://ipinfo.io/8.8.8.8/json/",
        timeout=5,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert token not in http_get.call_args.args[0]


@pytest.mark.parametrize("status_code", [401, 403, 429])
def test_auth_and_rate_limit_errors_do_not_log_token(status_code, monkeypatch, caplog):
    token = "ipinfo-test-secret-not-real"
    monkeypatch.setenv("IPINFO_TOKEN", token)
    response = Mock()
    error = requests.exceptions.HTTPError(f"request failed with token {token}")
    error.response = Mock(status_code=status_code)
    response.raise_for_status.side_effect = error

    with patch.object(geolocation.requests, "get", return_value=response):
        with caplog.at_level("WARNING", logger="process.geolocation"):
            assert geolocation.get_location("8.8.8.8") is None

    assert f"http_status={status_code}" in caplog.text
    assert token not in caplog.text


def test_network_exception_details_do_not_leak_token(monkeypatch, caplog):
    token = "ipinfo-test-secret-not-real"
    monkeypatch.setenv("IPINFO_TOKEN", token)

    with patch.object(
        geolocation.requests,
        "get",
        side_effect=requests.exceptions.ConnectionError(f"failed with token {token}"),
    ):
        with caplog.at_level("ERROR", logger="process.geolocation"):
            assert geolocation.get_location("8.8.8.8") is None

    assert "IPinfo network request failed" in caplog.text
    assert token not in caplog.text
