"""
Normalization utilities for signature analysis.

This module canonicalizes inputs by decoding URL encoding, HTML entities,
and repeated encodings to reduce evasion and improve signature coverage.
"""

from __future__ import annotations

import html
import re
from urllib.parse import unquote_plus


ENCODING_PATTERN = re.compile(r"%(?:[0-9A-Fa-f]{2})")


def decode_payload(value: str) -> str:
    """Decode URL-encoded and HTML-escaped payloads up to a few times."""
    normalized = value
    for _ in range(3):
        previous = normalized
        normalized = unquote_plus(normalized)
        normalized = html.unescape(normalized)
        if normalized == previous:
            break
    return normalized


def canonicalize_request_field(value: str) -> str:
    """Normalize a request field for signature scanning.

    Normalization includes URL-decoding, HTML entity decoding, and
    repeated decoding rounds to surface evasion payloads.
    """
    if not value:
        return ""

    normalized = decode_payload(value)
    # Remove repeated whitespace and normalize common obfuscation artifacts.
    normalized = re.sub(r"[\s\u00A0]+", " ", normalized).strip()
    return normalized


def build_scan_values(value: str) -> list[str]:
    """Return raw and normalized values to inspect for a request field."""
    normalized = canonicalize_request_field(value)
    if normalized and normalized != value:
        return [value, normalized]
    return [value]
