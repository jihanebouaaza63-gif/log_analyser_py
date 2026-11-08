"""Parse authentication and SSH syslog lines into structured events."""

import ipaddress
import logging
import re
from datetime import datetime


logger = logging.getLogger(__name__)

_HEADER = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<service>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_AUTH_PATTERNS = (
    ("ssh_success", "success", re.compile(
        r"^Accepted password for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)\b"
    )),
    ("ssh_success", "success", re.compile(
        r"^Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)\b"
    )),
    ("ssh_failed_password", "failure", re.compile(
        r"^Failed password for (?:(?P<invalid>invalid user)\s+)?(?P<username>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)\b"
    )),
    ("ssh_failed_publickey", "failure", re.compile(
        r"^Failed publickey for (?:(?P<invalid>invalid user)\s+)?(?P<username>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)\b"
    )),
    ("ssh_failed_keyboard_interactive", "failure", re.compile(
        r"^Failed keyboard-interactive/pam for (?P<username>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)\b"
    )),
)
_INVALID_USER = re.compile(
    r"^Invalid user(?:\s+(?P<username>\S+))?\s+from (?P<ip>\S+) port (?P<port>\d+)\b"
)
_CRON_PATTERNS = (
    ("cron_session_opened", re.compile(
        r"^pam_unix\(cron:session\): session opened for user (?P<username>\S+)"
        r"\(uid=\d+\) by \(uid=\d+\)$"
    )),
    ("cron_session_closed", re.compile(
        r"^pam_unix\(cron:session\): session closed for user (?P<username>\S+)$"
    )),
)
_CONNECTION_CONTEXT = re.compile(
    r"(?:(?:authenticating|invalid) user (?P<username>\S+)\s+)?"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+) port (?P<port>\d+)\b"
)
_PAM_CONTEXT = re.compile(r"\brhost=(?P<ip>\S+)(?:\s+.*?\buser=(?P<username>\S+))?")
_SSH_OTHER_PATTERNS = (
    ("pam_authentication_failure", re.compile(r"^pam_unix\(sshd:auth\): authentication failure;")),
    ("pam_unknown_user", re.compile(r"^pam_unix\(sshd:auth\): check pass; user unknown$")),
    ("ssh_connection_closed", re.compile(r"^Connection closed by ")),
    ("ssh_connection_closed", re.compile(r"^Disconnecting authenticating user ")),
    ("ssh_disconnected", re.compile(r"^Disconnected from ")),
    ("ssh_connection_reset", re.compile(r"^Connection reset by ")),
    ("ssh_received_disconnect", re.compile(r"^Received disconnect from ")),
    ("ssh_protocol_error", re.compile(r"^(?:error:|banner exchange:|userauth_pubkey:)")),
    ("ssh_authentication_notice", re.compile(r"^PAM (?:\d+ more authentication failures|service\(sshd\))")),
    ("ssh_repeated_message", re.compile(r"^message repeated \d+ times:")),
)


def _log_missing_fields(event_type, fields):
    missing = [name for name, value in fields if value is None]
    if missing:
        logger.warning(
            "Log field missing: event_type=%s fields=%s operation=extract_event",
            event_type,
            ",".join(missing),
        )


def extract_from_row(row):
    """Return one structured event, or ``None`` for an unrecognized line."""
    try:
        if not isinstance(row, str):
            raise TypeError("log row must be a string")

        match = _HEADER.match(row.rstrip("\r\n"))
        if not match:
            logger.warning(
                "Unrecognized log line: error_type=HeaderNotRecognized "
                "cause=expected_syslog_header operation=parse_header",
            )
            return None

        timestamp = match.group("timestamp")
        try:
            # Syslog auth.log timestamps omit the year; use a leap year only to
            # validate month/day/time, while preserving the original timestamp.
            datetime.strptime(f"{timestamp} 2000", "%b %d %H:%M:%S %Y")
        except ValueError as error:
            logger.warning(
                "Invalid log date: error_type=%s operation=validate_timestamp",
                type(error).__name__,
            )
            return None

        message = match.group("message")
        event_type = None
        result = None
        username = source_ip = source_port = None
        invalid_user = False
        counts_as_attempt = False
        invalid_source_ip = False
        invalid_source_port = False

        for candidate_type, candidate_result, pattern in _AUTH_PATTERNS:
            event_match = pattern.match(message)
            if event_match:
                event_type = candidate_type
                result = candidate_result
                username = event_match.group("username")
                source_ip = event_match.group("ip")
                source_port = event_match.group("port")
                invalid_user = bool(event_match.groupdict().get("invalid"))
                counts_as_attempt = True
                break

        if event_type is None:
            event_match = _INVALID_USER.match(message)
            if event_match:
                event_type = "ssh_invalid_user"
                username = event_match.group("username")
                source_ip = event_match.group("ip")
                source_port = event_match.group("port")
                invalid_user = True

        if event_type is None:
            for candidate_type, pattern in _CRON_PATTERNS:
                event_match = pattern.match(message)
                if event_match:
                    event_type = candidate_type
                    username = event_match.group("username")
                    break

        if event_type is None:
            for candidate_type, pattern in _SSH_OTHER_PATTERNS:
                if pattern.match(message):
                    event_type = candidate_type
                    # PAM authentication failure is evidence of a failure,
                    # but is ancillary to the SSH attempt and must not count twice.
                    if candidate_type == "pam_authentication_failure":
                        result = "failure"
                    break

        if event_type is None:
            logger.warning(
                "Unrecognized log line: error_type=EventNotRecognized "
                "cause=no_supported_event_pattern operation=classify_event",
            )
            return None

        # Ancillary SSH/PAM messages can also carry useful connection context.
        if source_ip is None or username is None or source_port is None:
            context = _CONNECTION_CONTEXT.search(message)
            if context:
                username = username or context.group("username")
                source_ip = source_ip or context.group("ip")
                source_port = source_port or context.group("port")
            pam_context = _PAM_CONTEXT.search(message)
            if pam_context:
                source_ip = source_ip or pam_context.group("ip")
                username = username or pam_context.group("username")

        if source_ip is not None:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError as error:
                invalid_source_ip = True
                logger.warning(
                    "Invalid source IP: error_type=%s operation=validate_ip",
                    type(error).__name__,
                )
                source_ip = None

        if source_port is not None:
            try:
                source_port = int(source_port)
                if not 0 <= source_port <= 65535:
                    raise ValueError("port outside valid range 0-65535")
            except ValueError as error:
                invalid_source_port = True
                logger.warning(
                    "Invalid source port: error_type=%s operation=validate_port",
                    type(error).__name__,
                )
                source_port = None

        if event_type in {
            "ssh_success", "ssh_failed_password", "ssh_failed_publickey",
            "ssh_failed_keyboard_interactive", "ssh_invalid_user",
        }:
            _log_missing_fields(
                event_type,
                (
                    ("username", username),
                    ("source_ip", source_ip if not invalid_source_ip else "<invalid>"),
                    ("source_port", source_port if not invalid_source_port else "<invalid>"),
                ),
            )

        return {
            "event_time": timestamp,
            "hostname": match.group("hostname"),
            "service": match.group("service"),
            "pid": int(match.group("pid")) if match.group("pid") else None,
            "event_type": event_type,
            "result": result,
            "username": username,
            "source_ip": source_ip,
            "source_port": source_port,
            "invalid_user": invalid_user,
            "counts_as_attempt": counts_as_attempt,
            "original_line": row,
        }
    except Exception:
        logger.exception(
            "Log transformation failed: error_type=TransformationError "
            "operation=extract_from_row",
        )
        return None


def extract(rows):
    """Transform an iterable of raw lines into a list of event dictionaries."""
    events = []
    try:
        for row in rows:
            event = extract_from_row(row)
            if event is not None:
                events.append(event)
    except Exception:
        logger.exception(
            "Log transformation failed: error_type=TransformationError "
            "operation=iterate_rows"
        )
    return events
