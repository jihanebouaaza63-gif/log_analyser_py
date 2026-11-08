"""Integration tests for the command-line pipeline and generated dashboard."""

import json
import re
from unittest.mock import Mock, patch

import pytest

import process.geolocation as geolocation
from main import main, run_pipeline


@pytest.fixture(autouse=True)
def clear_geolocation_cache(monkeypatch):
    geolocation._LOCATION_CACHE.clear()
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    yield
    geolocation._LOCATION_CACHE.clear()


def write_auth_log(directory):
    directory.mkdir(parents=True)
    (directory / "auth.log.1").write_text(
        "May 19 08:49:50 host sshd[101]: Failed password for invalid user scanner from 8.8.8.8 port 5001 ssh2\n"
        "May 19 08:49:51 host sshd[102]: Failed password for root from 1.1.1.1 port 5002 ssh2\n"
        "May 19 08:49:52 host sshd[103]: Accepted password for alice from 8.8.4.4 port 5003 ssh2\n"
        "May 19 08:49:53 host sshd[104]: Invalid user scanner from 8.8.8.8 port 5001\n",
        encoding="utf-8",
    )


def test_cli_no_enrich_builds_dashboard_from_parsed_pipeline_events(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "results"
    write_auth_log(input_dir)

    with patch("main.enrich_events") as enrich:
        assert main([
            "--input-dir", str(input_dir),
            "--output-dir", str(output_dir),
            "--log-dir", str(tmp_path / "logs"),
            "--no-enrich",
        ]) == 0

    enrich.assert_not_called()
    index_path = output_dir / "index.html"
    summary_path = output_dir / "summary.json"
    assert index_path.is_file()
    assert summary_path.is_file()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    page = index_path.read_text(encoding="utf-8")
    assert summary["failed_attempts_by_country"] == {"Inconnu / non enrichi": 2}
    assert summary["successful_connections_by_user"] == {"alice": 1}
    assert summary["failed_invalid_user_attempts"] == 1
    assert summary["total_counted_attempts"] == 3
    assert len(re.findall(r"<svg\b", page)) == 2
    assert "data-category=\"Inconnu / non enrichi\" data-count=\"2\"" in page
    assert "data-category=\"alice\" data-count=\"1\"" in page


def test_full_pipeline_uses_mocked_geolocation_and_real_parsed_events(tmp_path):
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "results"
    write_auth_log(input_dir)

    def mocked_ipinfo(url, **kwargs):
        response = Mock()
        if "8.8.8.8" in url:
            country = "US"
        elif "1.1.1.1" in url:
            country = "AU"
        else:
            country = "US"
        response.json.return_value = {"country": country}
        return response

    with patch.object(geolocation.requests, "get", side_effect=mocked_ipinfo) as http_get:
        summary = run_pipeline(input_dir, output_dir, enrich=True, log_dir=tmp_path / "logs")

    assert http_get.call_count == 3
    assert summary["failed_attempts_by_country"] == {"AU": 1, "US": 1}
    assert summary["successful_connections_by_user"] == {"alice": 1}
    assert summary["failed_invalid_user_attempts"] == 1
    assert json.loads((output_dir / "summary.json").read_text(encoding="utf-8")) == summary
    page = (output_dir / "index.html").read_text(encoding="utf-8")
    assert "data-category=\"AU\" data-count=\"1\"" in page
    assert "data-category=\"US\" data-count=\"1\"" in page
    assert len(re.findall(r"<svg\b", page)) == 2


def test_dashboard_write_errors_are_propagated(tmp_path):
    input_dir = tmp_path / "input"
    write_auth_log(input_dir)
    output_path = tmp_path / "not-a-directory"
    output_path.write_text("occupied", encoding="utf-8")

    with patch("main.enrich_events"):
        with pytest.raises(FileExistsError):
            run_pipeline(input_dir, output_path, enrich=False, log_dir=tmp_path / "logs")

    log_text = (tmp_path / "logs" / "pipeline.log").read_text(encoding="utf-8")
    assert "Dashboard output failed: error_type=FileExistsError" in log_text
    assert log_text.count("Dashboard output failed") == 1
