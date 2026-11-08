"""Aggregate parsed events and render a dependency-free HTML dashboard."""

import html
import json
from collections import Counter
from pathlib import Path


UNKNOWN_COUNTRY = "Inconnu / non enrichi"
MULTIPLE_COUNTRIES = "Plusieurs pays"
UNKNOWN_USER = "Inconnu / utilisateur absent"


def _source_ips(event):
    """Return unique source IP values carried by one event."""
    values = event.get("source_ips")
    if values is None:
        values = event.get("source_ip")
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def _geolocation_entries(event):
    """Normalize single, list, or IP-keyed geolocation data."""
    per_ip = event.get("geolocations")
    if isinstance(per_ip, dict) and "country" not in per_ip:
        entries = []
        for ip, value in per_ip.items():
            if isinstance(value, dict):
                entry = value.copy()
                entry.setdefault("ip", ip)
                entries.append(entry)
        return entries
    if isinstance(per_ip, (list, tuple)):
        return [entry for entry in per_ip if isinstance(entry, dict)]
    if isinstance(per_ip, dict):
        return [per_ip]

    location = event.get("geolocation")
    if isinstance(location, dict):
        return [location]
    if isinstance(location, (list, tuple)):
        return [entry for entry in location if isinstance(entry, dict)]
    return []


def _country_for_event(event):
    """Choose one country bucket per event, including multi-IP events."""
    ips = _source_ips(event)
    entries = _geolocation_entries(event)

    if len(ips) > 1:
        locations_by_ip = {
            entry.get("ip"): entry
            for entry in entries
            if entry.get("ip") in ips
        }
        if len(locations_by_ip) != len(ips):
            return UNKNOWN_COUNTRY
        countries = {entry.get("country") for entry in locations_by_ip.values()}
        if None in countries or "" in countries:
            return UNKNOWN_COUNTRY
        if len(countries) > 1:
            return MULTIPLE_COUNTRIES
        return next(iter(countries))

    if len(ips) == 1:
        matching = [entry for entry in entries if entry.get("ip") in (None, ips[0])]
        if not matching:
            return UNKNOWN_COUNTRY
        country = matching[0].get("country")
        return country if isinstance(country, str) and country.strip() else UNKNOWN_COUNTRY

    return UNKNOWN_COUNTRY


def _attempt_identity(event):
    """Build a stable identity so duplicated source events count only once."""
    event_id = event.get("event_id")
    if event_id is not None:
        return ("event_id", str(event_id))

    original_line = event.get("original_line")
    if isinstance(original_line, str) and original_line:
        return ("original_line", original_line)

    return (
        "fields",
        event.get("event_time"),
        event.get("hostname"),
        event.get("service"),
        event.get("pid"),
        event.get("event_type"),
        event.get("result"),
        event.get("username"),
        tuple(sorted(_source_ips(event))),
        event.get("source_port"),
    )


def aggregate_events(events):
    """Aggregate counted authentication attempts from pipeline event dictionaries."""
    failed_by_country = Counter()
    successful_by_user = Counter()
    invalid_user_failures = 0
    failed_total = 0
    successful_total = 0
    seen_attempts = set()

    for event in events:
        if not isinstance(event, dict) or event.get("counts_as_attempt") is not True:
            continue
        result = event.get("result")
        if result not in ("failure", "success"):
            continue

        identity = _attempt_identity(event)
        if identity in seen_attempts:
            continue
        seen_attempts.add(identity)

        if result == "failure":
            failed_total += 1
            failed_by_country[_country_for_event(event)] += 1
            if event.get("invalid_user") is True:
                invalid_user_failures += 1
        else:
            successful_total += 1
            username = event.get("username")
            if not isinstance(username, str) or not username.strip():
                username = UNKNOWN_USER
            successful_by_user[username] += 1

    return {
        "failed_attempts_by_country": dict(sorted(failed_by_country.items())),
        "successful_connections_by_user": dict(sorted(successful_by_user.items())),
        "failed_invalid_user_attempts": invalid_user_failures,
        "total_failed_attempts": failed_total,
        "total_successful_connections": successful_total,
        "total_counted_attempts": failed_total + successful_total,
    }


def _render_bar_chart(title, values, color):
    """Render every category in an aggregate as an SVG horizontal bar chart."""
    width = 1000
    row_height = 38
    top = 48
    height = max(100, top + row_height * len(values) + 12)
    label_width = 300
    chart_width = width - label_width - 90
    maximum = max(values.values(), default=0) or 1
    rows = []

    for index, (label, count) in enumerate(values.items()):
        y = top + index * row_height
        bar_width = round(chart_width * count / maximum)
        safe_label = html.escape(str(label), quote=True)
        rows.append(
            f'<g class="bar" data-category="{safe_label}" data-count="{count}">'
            f'<text x="{label_width - 12}" y="{y + 19}" text-anchor="end">'
            f"{html.escape(str(label))}</text>"
            f'<rect x="{label_width}" y="{y}" width="{bar_width}" height="24" '
            f'rx="3" fill="{color}" />'
            f'<text x="{label_width + bar_width + 8}" y="{y + 18}">{count}</text>'
            "</g>"
        )

    if not rows:
        rows.append('<text x="24" y="80">Aucune donnée</text>')
    return (
        f'<svg class="chart" role="img" aria-label="{html.escape(title, quote=True)}" '
        f'viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
        f"<text class=\"chart-title\" x=\"20\" y=\"28\">{html.escape(title)}</text>"
        f"{''.join(rows)}</svg>"
    )


def render_dashboard(summary):
    """Render dashboard HTML using the same aggregates written to summary.json."""
    failed_chart = _render_bar_chart(
        "Tentatives échouées par pays",
        summary["failed_attempts_by_country"],
        "#c0392b",
    )
    success_chart = _render_bar_chart(
        "Connexions réussies par utilisateur",
        summary["successful_connections_by_user"],
        "#2874a6",
    )
    invalid_count = summary["failed_invalid_user_attempts"]
    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pipeline Log Analyser — Dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #202124; }}
    section {{ margin: 2rem 0; overflow-x: auto; }}
    svg {{ min-width: 760px; width: 100%; height: auto; }}
    svg text {{ font: 14px system-ui, sans-serif; fill: #202124; }}
    svg .chart-title {{ font-weight: 700; font-size: 17px; }}
    .stat {{ background: #f3f5f7; border-radius: 8px; padding: 1rem 1.25rem; display: inline-block; }}
    .stat strong {{ display: block; font-size: 1.8rem; }}
  </style>
</head>
<body>
  <h1>Pipeline Log Analyser</h1>
  <div class="stat"><span>Tentatives échouées avec utilisateur invalide</span>
    <strong>{invalid_count}</strong></div>
  <section>{failed_chart}</section>
  <section>{success_chart}</section>
</body>
</html>
"""


def build_dashboard(events, output_dir):
    """Write summary.json and index.html from the same event aggregates."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary = aggregate_events(events)
    (output_path / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_path / "index.html").write_text(
        render_dashboard(summary),
        encoding="utf-8",
    )
    return summary
