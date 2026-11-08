"""Tests for pipeline log configuration, levels, redaction, and error records."""

import logging
import re

from main import configure_logging
from process.extract_transforme import extract_from_row


def close_pipeline_handlers(root_logger):
    for handler in list(root_logger.handlers):
        if getattr(handler, "_log_analyser_handler", False):
            root_logger.removeHandler(handler)
            handler.close()


def test_file_logging_has_timestamp_level_module_and_redacts_secrets(tmp_path, monkeypatch):
    secret = "fake-ipinfo-token-for-test"
    monkeypatch.setenv("IPINFO_TOKEN", secret)
    root_logger = logging.getLogger()
    previous_level = root_logger.level

    try:
        log_path = configure_logging(tmp_path / "logs")
        configure_logging(tmp_path / "logs")
        module_logger = logging.getLogger("tests.test_logging")
        module_logger.debug("debug detail")
        module_logger.info("pipeline stage complete")
        module_logger.warning("invalid event fields")
        module_logger.error("Authorization: Bearer %s password=%s", secret, secret)
        try:
            raise RuntimeError(f"request failed with token={secret}")
        except RuntimeError:
            module_logger.exception("request exception")

        text = log_path.read_text(encoding="utf-8")
        records = re.findall(
            r"(?m)^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} "
            r"(DEBUG|INFO|WARNING|ERROR) tests\.test_logging ",
            text,
        )
        assert records == ["DEBUG", "INFO", "WARNING", "ERROR", "ERROR"]
        assert "[REDACTED]" in text
        assert secret not in text
        assert text.count("request exception") == 1
        assert len(
            [h for h in root_logger.handlers if getattr(h, "_log_analyser_handler", False)]
        ) == 1
    finally:
        close_pipeline_handlers(root_logger)
        root_logger.setLevel(previous_level)


def test_parser_warning_does_not_write_raw_log_line(tmp_path):
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    sensitive_line = (
        "not a valid syslog header username=private-user source_ip=203.0.113.25\n"
    )
    try:
        log_path = configure_logging(tmp_path / "logs")
        assert extract_from_row(sensitive_line) is None
        text = log_path.read_text(encoding="utf-8")
        assert "Unrecognized log line" in text
        assert "private-user" not in text
        assert "203.0.113.25" not in text
    finally:
        close_pipeline_handlers(root_logger)
        root_logger.setLevel(previous_level)
