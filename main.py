"""Command-line entry point for the log analysis pipeline."""

import argparse
import logging
import os
import re
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ingestion.raw import toRows
from process.extract_transforme import extract
from process.geolocation import enrich_events
from serving.dashboard import build_dashboard


logger = logging.getLogger(__name__)


class _SensitiveDataFilter(logging.Filter):
    """Redact tokens and password-like values before writing records."""

    _secret_patterns = (
        re.compile(r"(?i)(\bauthorization\s*[:=]\s*bearer\s+)([^\s,;]+)"),
        re.compile(
            r"(?i)([\"']?\b(?:ipinfo[_-]?token|api[_-]?key|access[_-]?token|token|password|passwd)[\"']?\s*[:=]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
    )

    def __init__(self, secrets=()):
        super().__init__()
        self._secrets = tuple(secret for secret in secrets if secret)

    def _redact(self, value):
        for secret in self._secrets:
            value = value.replace(secret, "[REDACTED]")
        for pattern in self._secret_patterns:
            value = pattern.sub(r"\1[REDACTED]", value)
        return value

    def filter(self, record):
        record.msg = self._redact(record.getMessage())
        record.args = ()
        if record.exc_info:
            exception_text = "".join(traceback.format_exception(*record.exc_info))
            record.exc_text = self._redact(exception_text)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._redact(record.exc_text)
        return True


def configure_logging(log_dir="logs"):
    """Configure one rotating, redacting log file outside the auth.log folder."""
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    log_path = (directory / "pipeline.log").resolve()
    root_logger = logging.getLogger()

    for handler in list(root_logger.handlers):
        if getattr(handler, "_log_analyser_handler", False):
            root_logger.removeHandler(handler)
            handler.close()

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    file_handler.addFilter(_SensitiveDataFilter((os.environ.get("IPINFO_TOKEN"),)))
    file_handler._log_analyser_handler = True
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.DEBUG)
    return log_path


def run_pipeline(input_dir="data", output_dir="results", enrich=True, log_dir="logs"):
    """Run ingestion, parsing, optional geolocation, and dashboard generation."""
    configure_logging(log_dir)
    logger.info("Pipeline started")
    rows = toRows(input_dir)
    logger.debug("Ingestion completed rows=%d", len(rows))
    events = extract(rows)
    logger.info("Parsing completed events=%d", len(events))
    if enrich:
        logger.info("IP geolocation enrichment enabled")
        events = enrich_events(events)
    else:
        logger.info("IP geolocation enrichment skipped")
    summary = build_dashboard(events, output_dir)
    logger.info(
        "Dashboard generation completed attempts=%d",
        summary["total_counted_attempts"],
    )
    return summary


def main(argv=None):
    """Parse command-line options and run the complete pipeline."""
    parser = argparse.ArgumentParser(description="Analyse auth.log files and build a dashboard.")
    parser.add_argument(
        "--input-dir",
        default="data",
        help="Directory containing auth.log files (default: data)",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory for index.html and summary.json (default: results)",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip IP geolocation and build the dashboard from parsed events only",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for pipeline logs (default: logs)",
    )
    args = parser.parse_args(argv)
    run_pipeline(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        enrich=not args.no_enrich,
        log_dir=args.log_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
