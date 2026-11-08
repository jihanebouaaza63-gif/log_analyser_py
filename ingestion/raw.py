"""Read authentication log files from a directory."""

import gzip
import logging
import re
import zlib
from pathlib import Path


logger = logging.getLogger(__name__)

# Match auth.log and rotated names such as auth.log.1 and auth.log.2.gz.
_AUTH_LOG_NAME = re.compile(r"^auth\.log(?:\.\d+)?(?:\.gz)?$")


def toRows(path):
    """Return lines from all auth.log files in *path*, in filename order.

    Plain text and gzip files are supported. A file that cannot be opened or
    read is logged and skipped so the remaining files can still be ingested.
    Invalid UTF-8 bytes are replaced rather than stopping the import.
    """
    directory = Path(path)
    try:
        candidates = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError as error:
        logger.error(
            "Ingestion failed: file=%s error_type=%s cause=%s operation=list_directory",
            directory,
            type(error).__name__,
            error,
            exc_info=True,
        )
        return []

    rows = []
    for file_path in candidates:
        if not file_path.is_file() or not _AUTH_LOG_NAME.match(file_path.name):
            continue

        opener = gzip.open if file_path.name.endswith(".gz") else open
        try:
            with opener(file_path, mode="rt", encoding="utf-8", errors="replace") as log_file:
                rows.extend(log_file.readlines())
        except (OSError, EOFError, UnicodeError, zlib.error) as error:
            logger.error(
                "Ingestion failed: file=%s error_type=%s cause=%s operation=read_file",
                file_path,
                type(error).__name__,
                error,
                exc_info=True,
            )

    return rows


if __name__ == "__main__":
    print(toRows("./data")[:10])
