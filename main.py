"""Command-line entry point for the log analysis pipeline."""

import argparse

from ingestion.raw import toRows
from process.extract_transforme import extract
from process.geolocation import enrich_events
from serving.dashboard import build_dashboard


def run_pipeline(input_dir="data", output_dir="results", enrich=True):
    """Run ingestion, parsing, optional geolocation, and dashboard generation."""
    rows = toRows(input_dir)
    events = extract(rows)
    if enrich:
        events = enrich_events(events)
    return build_dashboard(events, output_dir)


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
    args = parser.parse_args(argv)
    run_pipeline(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        enrich=not args.no_enrich,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
