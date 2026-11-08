"""Tests for dashboard aggregates and their HTML/JSON consistency."""

import html
import json
import re

from serving.dashboard import (
    MULTIPLE_COUNTRIES,
    UNKNOWN_COUNTRY,
    UNKNOWN_USER,
    aggregate_events,
    build_dashboard,
)


def failed_event(line, **overrides):
    event = {
        "event_time": "May 19 08:49:50",
        "hostname": "host",
        "service": "sshd",
        "pid": 123,
        "event_type": "failed_password",
        "result": "failure",
        "username": "scanner",
        "source_ip": "8.8.8.8",
        "source_port": 5000,
        "invalid_user": False,
        "counts_as_attempt": True,
        "original_line": line,
    }
    event.update(overrides)
    return event


def success_event(line, username):
    return {
        "event_time": "May 19 08:49:50",
        "hostname": "host",
        "service": "sshd",
        "pid": 123,
        "event_type": "accepted_password",
        "result": "success",
        "username": username,
        "source_ip": "8.8.8.8",
        "source_port": 5000,
        "invalid_user": False,
        "counts_as_attempt": True,
        "original_line": line,
    }


def chart_counts(svg):
    return {
        html.unescape(category): int(count)
        for category, count in re.findall(
            r'<g class="bar" data-category="([^"]*)" data-count="(\d+)"',
            svg,
        )
    }


def test_all_countries_and_users_are_included_without_top_15_limit():
    events = []
    for index in range(18):
        events.append(
            failed_event(
                f"failure-{index}",
                geolocation={"ip": "8.8.8.8", "country": f"Country-{index:02d}"},
            )
        )
        events.append(success_event(f"success-{index}", f"user-{index:02d}"))

    summary = aggregate_events(events)

    assert len(summary["failed_attempts_by_country"]) == 18
    assert len(summary["successful_connections_by_user"]) == 18
    assert summary["total_failed_attempts"] == 18
    assert summary["total_successful_connections"] == 18


def test_missing_ip_and_enrichment_are_counted_as_unknown_once_per_attempt():
    events = [
        failed_event("missing-ip", source_ip=None, geolocation=None),
        failed_event("unresolved-ip", geolocation=None),
        failed_event("same-ip-first", geolocation={"country": "US"}),
        failed_event("same-ip-second", geolocation={"country": "US"}),
    ]

    summary = aggregate_events(events)

    assert summary["failed_attempts_by_country"] == {
        "US": 2,
        UNKNOWN_COUNTRY: 2,
    }
    assert summary["total_failed_attempts"] == 4


def test_multi_ip_attempt_is_counted_once_and_country_mapping_is_explicit():
    events = [
        failed_event(
            "two-countries",
            source_ip=None,
            source_ips=["8.8.8.8", "1.1.1.1"],
            geolocations=[
                {"ip": "8.8.8.8", "country": "US"},
                {"ip": "1.1.1.1", "country": "AU"},
            ],
        ),
        failed_event(
            "partial-enrichment",
            source_ip=None,
            source_ips=["8.8.8.8", "1.1.1.1"],
            geolocations=[{"ip": "8.8.8.8", "country": "US"}],
        ),
    ]

    summary = aggregate_events(events)

    assert summary["failed_attempts_by_country"] == {
        MULTIPLE_COUNTRIES: 1,
        UNKNOWN_COUNTRY: 1,
    }
    assert sum(summary["failed_attempts_by_country"].values()) == 2


def test_duplicate_attempt_and_invalid_user_detection_are_not_double_counted():
    failed = failed_event("one-failed-attempt", invalid_user=True)
    duplicate = failed.copy()
    detection_only = failed_event(
        "invalid-user-detection",
        event_type="invalid_user",
        result=None,
        counts_as_attempt=False,
        invalid_user=True,
    )

    summary = aggregate_events([failed, duplicate, detection_only])

    assert summary["total_failed_attempts"] == 1
    assert summary["failed_invalid_user_attempts"] == 1


def test_missing_success_username_has_explicit_bucket():
    summary = aggregate_events([success_event("no-user", None)])

    assert summary["successful_connections_by_user"] == {UNKNOWN_USER: 1}


def test_dashboard_graphs_match_summary_json_with_all_categories(tmp_path):
    events = []
    for index in range(17):
        events.append(
            failed_event(
                f"failure-{index}",
                geolocation={"ip": "8.8.8.8", "country": f"Country-{index:02d}"},
                invalid_user=index == 0,
            )
        )
        events.append(success_event(f"success-{index}", f"user-{index:02d}"))

    returned_summary = build_dashboard(events, tmp_path)
    saved_summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    svgs = re.findall(r"<svg\b.*?</svg>", page, flags=re.DOTALL)

    assert len(svgs) == 2
    assert returned_summary == saved_summary
    assert chart_counts(svgs[0]) == saved_summary["failed_attempts_by_country"]
    assert chart_counts(svgs[1]) == saved_summary["successful_connections_by_user"]
    assert "Tentatives échouées avec utilisateur invalide" in page
    assert saved_summary["failed_invalid_user_attempts"] == 1
    assert len(chart_counts(svgs[0])) == 17
    assert len(chart_counts(svgs[1])) == 17
