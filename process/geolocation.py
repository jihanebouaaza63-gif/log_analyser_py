
"""IPinfo-based geolocation helpers for parsed authentication events."""

import ipaddress
import logging
import os

import requests


logger = logging.getLogger(__name__)

IPINFO_URL = "https://ipinfo.io/{ip}/json/"
REQUEST_TIMEOUT = 5

# Process-local cache. Only successful lookups are cached.
_LOCATION_CACHE = {}


def _public_ip(value):
    """Return a canonical public IP address, or None if it is not public."""
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as error:
        logger.warning(
            "Geolocation skipped: error_type=%s operation=validate_ip",
            type(error).__name__,
        )
        return None

    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        logger.debug(
            "Geolocation skipped: non-public IP operation=validate_ip ip=%s",
            address,
        )
        return None

    return str(address)


def get_location(ip):
    """Return normalized IPinfo fields for a public IP, or None on failure.

    Successful responses are cached in memory by canonical IP address.
    """
    public_ip = _public_ip(ip)

    if public_ip is None:
        return None

    cached = _LOCATION_CACHE.get(public_ip)
    if cached is not None:
        return cached.copy()

    try:
        token = os.environ.get("IPINFO_TOKEN", "").strip()

        request_options = {"timeout": REQUEST_TIMEOUT}

        if token:
            request_options["headers"] = {
                "Authorization": f"Bearer {token}"
            }

        response = requests.get(
            IPINFO_URL.format(ip=public_ip),
            **request_options,
        )
        response.raise_for_status()

    except requests.exceptions.HTTPError as error:
        status_code = getattr(
            getattr(error, "response", None),
            "status_code",
            None,
        )

        if status_code is None:
            status_code = getattr(
                locals().get("response"),
                "status_code",
                None,
            )

        if status_code in (401, 403):
            logger.warning(
                "IPinfo authentication rejected: http_status=%s "
                "operation=http_request",
                status_code,
            )
        elif status_code == 429:
            logger.warning(
                "IPinfo rate limit reached: http_status=429 "
                "operation=http_request"
            )
        else:
            logger.error(
                "IPinfo HTTP request failed: http_status=%s "
                "operation=http_request",
                status_code,
            )

        return None

    except requests.exceptions.RequestException as error:
        logger.error(
            "IPinfo network request failed: error_type=%s "
            "operation=http_request ip=%s",
            type(error).__name__,
            public_ip,
        )
        return None

    try:
        payload = response.json()

    except ValueError as error:
        logger.error(
            "IPinfo returned invalid JSON: error_type=%s "
            "operation=parse_json ip=%s",
            type(error).__name__,
            public_ip,
        )
        return None

    if not isinstance(payload, dict):
        logger.error(
            "IPinfo returned unexpected JSON: error_type=InvalidPayload "
            "cause=expected_object operation=validate_json ip=%s",
            public_ip,
        )
        return None

    location = {
        "ip": public_ip,
        "hostname": payload.get("hostname"),
        "city": payload.get("city"),
        "region": payload.get("region"),
        "country": payload.get("country"),
        "location": payload.get("loc"),
        "organization": payload.get("org"),
        "postal": payload.get("postal"),
        "timezone": payload.get("timezone"),
    }

    _LOCATION_CACHE[public_ip] = location

    return location.copy()


def enrich_events(events):
    """Return event dictionaries with a geolocation field added.

    Events are copied and retained even if their IP is missing or
    a lookup fails.
    """
    enriched = []

    try:
        for index, event in enumerate(events):

            if not isinstance(event, dict):
                logger.warning(
                    "Event not enriched: error_type=InvalidEvent "
                    "cause=expected_dictionary operation=enrich_events "
                    "index=%s",
                    index,
                )
                enriched.append(event)
                continue

            enriched_event = event.copy()

            try:
                source_ip = event.get("source_ip")

                if source_ip:
                    enriched_event["geolocation"] = get_location(source_ip)
                else:
                    enriched_event["geolocation"] = None

            except Exception:
                logger.error(
                    "Event geolocation failed: error_type=GeolocationError "
                    "operation=enrich_event index=%s",
                    index,
                )
                enriched_event["geolocation"] = None

            enriched.append(enriched_event)

    except Exception as error:
        logger.error(
            "Event enrichment stopped: error_type=%s "
            "operation=iterate_events",
            type(error).__name__,
        )

    return enriched
