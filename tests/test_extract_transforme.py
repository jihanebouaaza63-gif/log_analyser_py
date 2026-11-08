"""Unit tests for parsing synthetic SSH authentication log lines."""

import pytest

from process.extract_transforme import extract, extract_from_row


def make_row(message, timestamp="May 19 08:49:50", pid=1234):
    return f"{timestamp} test-host sshd[{pid}]: {message}\n"


def test_extracts_header_and_authentication_fields():
    row = make_row(
        "Accepted password for alice from 192.0.2.10 port 5001 ssh2",
        timestamp="May 19 08:49:50",
        pid=4321,
    )

    event = extract_from_row(row)

    assert event is not None
    assert event["event_time"] == "May 19 08:49:50"
    assert event["hostname"] == "test-host"
    assert event["service"] == "sshd"
    assert event["pid"] == 4321
    assert event["username"] == "alice"
    assert event["source_ip"] == "192.0.2.10"
    assert event["source_port"] == 5001
    assert event["original_line"] == row


@pytest.mark.parametrize(
    ("message", "event_type", "result"),
    [
        ("Accepted password for alice from 192.0.2.1 port 22 ssh2", "ssh_success", "success"),
        ("Accepted publickey for bob from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:abc", "ssh_success", "success"),
        ("Failed password for root from 192.0.2.2 port 23 ssh2", "ssh_failed_password", "failure"),
        ("Failed publickey for root from 192.0.2.3 port 24 ssh2", "ssh_failed_publickey", "failure"),
        ("Failed keyboard-interactive/pam for root from 192.0.2.4 port 25 ssh2", "ssh_failed_keyboard_interactive", "failure"),
    ],
)
def test_recognizes_authentication_results(message, event_type, result):
    event = extract_from_row(make_row(message))

    assert event is not None
    assert event["event_type"] == event_type
    assert event["result"] == result
    assert event["counts_as_attempt"] is True


def test_invalid_syslog_date_warns_and_returns_none(caplog):
    row = make_row(
        "Accepted password for alice from 192.0.2.1 port 22 ssh2",
        timestamp="Feb 30 08:49:50",
    )

    with caplog.at_level("WARNING", logger="process.extract_transforme"):
        event = extract_from_row(row)

    assert event is None
    assert "Invalid log date" in caplog.text


def test_invalid_user_detection_is_not_double_counted():
    rows = [
        make_row("Invalid user scanner from 192.0.2.10 port 5001", pid=100),
        make_row(
            "Failed password for invalid user scanner from 192.0.2.10 port 5001 ssh2",
            timestamp="May 19 08:49:51",
            pid=101,
        ),
    ]

    events = extract(rows)

    assert [event["event_type"] for event in events] == ["ssh_invalid_user", "ssh_failed_password"]
    assert events[0]["invalid_user"] is True
    assert events[0]["counts_as_attempt"] is False
    assert events[1]["invalid_user"] is True
    assert events[1]["counts_as_attempt"] is True
    assert sum(event["counts_as_attempt"] for event in events) == 1


@pytest.mark.parametrize(
    "message",
    [
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=192.0.2.10 user=root",
        "Connection closed by authenticating user root 192.0.2.10 port 5002 [preauth]",
        "Disconnected from invalid user scanner 192.0.2.10 port 5003 [preauth]",
    ],
)
def test_pam_and_ancillary_ssh_events_are_not_counted_as_attempts(message):
    event = extract_from_row(make_row(message))

    assert event is not None
    assert event["counts_as_attempt"] is False


def test_invalid_ip_is_rejected_and_logged(caplog):
    row = make_row("Failed password for root from 999.2.3.4 port 22 ssh2")

    with caplog.at_level("WARNING", logger="process.extract_transforme"):
        event = extract_from_row(row)

    assert event is not None
    assert event["source_ip"] is None
    assert event["counts_as_attempt"] is True
    assert "Invalid source IP" in caplog.text
    assert "Log field missing" not in caplog.text


def test_out_of_range_port_is_rejected_and_logged(caplog):
    row = make_row("Accepted password for alice from 192.0.2.10 port 65536 ssh2")

    with caplog.at_level("WARNING", logger="process.extract_transforme"):
        event = extract_from_row(row)

    assert event is not None
    assert event["source_port"] is None
    assert "Invalid source port" in caplog.text
    assert "Log field missing" not in caplog.text


def test_extract_processes_multiple_lines_and_skips_unrecognized(caplog):
    rows = [
        make_row("Accepted password for alice from 192.0.2.10 port 5001 ssh2"),
        "this line has no syslog header\n",
        make_row("Failed password for root from 192.0.2.11 port 5002 ssh2", pid=5678),
    ]

    with caplog.at_level("WARNING", logger="process.extract_transforme"):
        events = extract(rows)

    assert len(events) == 2
    assert [event["result"] for event in events] == ["success", "failure"]
    assert [event["pid"] for event in events] == [1234, 5678]
    assert "Unrecognized log line" in caplog.text
    assert extract_from_row(rows[1]) is None


@pytest.mark.parametrize(
    ("message", "event_type"),
    [
        (
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "cron_session_opened",
        ),
        (
            "pam_unix(cron:session): session closed for user root",
            "cron_session_closed",
        ),
    ],
)
def test_cron_session_events_are_recognized_but_not_ssh_attempts(message, event_type):
    row = f"May 24 00:09:01 host CRON[456]: {message}\n"

    event = extract_from_row(row)

    assert event is not None
    assert event["event_type"] == event_type
    assert event["service"] == "CRON"
    assert event["pid"] == 456
    assert event["username"] == "root"
    assert event["result"] is None
    assert event["counts_as_attempt"] is False


def test_ssh_disconnect_event_extracts_username_ip_and_port_without_counting_attempt():
    row = (
        "May 24 00:09:01 host sshd[1092397]: Disconnecting authenticating user root "
        "218.250.28.248 port 46508: Too many authentication failures [preauth]\n"
    )

    event = extract_from_row(row)

    assert event is not None
    assert event["event_type"] == "ssh_connection_closed"
    assert event["username"] == "root"
    assert event["source_ip"] == "218.250.28.248"
    assert event["source_port"] == 46508
    assert event["result"] is None
    assert event["counts_as_attempt"] is False


def test_invalid_user_with_empty_name_is_preserved_without_inventing_username():
    row = "May 24 00:09:01 host sshd[457]: Invalid user  from 31.56.209.38 port 51358\n"

    event = extract_from_row(row)

    assert event is not None
    assert event["event_type"] == "ssh_invalid_user"
    assert event["username"] is None
    assert event["source_ip"] == "31.56.209.38"
    assert event["source_port"] == 51358
    assert event["invalid_user"] is True
    assert event["counts_as_attempt"] is False
