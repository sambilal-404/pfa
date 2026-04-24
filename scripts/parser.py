#!/usr/bin/env python3
"""
parser.py
---------
Handles two input formats:

  A) Structured JSON:
     [{"method": "GET", "url": "/...", "headers": {}, "body": "", "ip": "...", "label": "..."}]

  B) Raw HTTP text (exported_requests.txt format):
     GET /api/users?id=1' OR '1'='1 HTTP/1.1
     Host: localhost
     User-Agent: ...
     
     [body if any]
     ---
     GET /api/users/1 HTTP/1.1
     ...

Usage:
  from scripts.parser import load_json_dataset, parse_raw_http_file, validate_record
"""

import json
import re
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Schema definition  (what every record MUST look like)
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = {"method", "url", "headers", "body", "ip", "label"}
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
VALID_LABELS  = {"legit", "attack", "unknown"}

STANDARD_TEMPLATE = {
    "method":      "GET",
    "url":         "/",
    "headers":     {},
    "body":        "",
    "ip":          "127.0.0.1",
    "label":       "unknown",    # "legit" | "attack" | "unknown"
    "attack_type": None,         # "SQL Injection" | "XSS" | etc.
    "raw_payload": None,         # original raw payload string (for debug)
    "source":      "unknown",    # which file/source this came from
}


def validate_record(record: dict, fix: bool = True) -> dict | None:
    """
    Validate and optionally fix a record.
    Returns None if the record is unfixable (missing URL, invalid method).
    """
    if fix:
        record = {**STANDARD_TEMPLATE, **record}  # fill missing fields with defaults

    # Must have a URL
    url = record.get("url", "").strip()
    if not url:
        return None

    # Normalize method
    method = record.get("method", "GET").upper().strip()
    if method not in VALID_METHODS:
        method = "GET"
    record["method"] = method

    # Ensure headers is a dict
    if not isinstance(record.get("headers"), dict):
        record["headers"] = {}

    # Ensure body is a string
    if record.get("body") is None:
        record["body"] = ""
    record["body"] = str(record["body"])

    # Ensure IP is present
    if not record.get("ip"):
        record["ip"] = "127.0.0.1"

    # Normalize label
    label = str(record.get("label", "unknown")).lower()
    if label not in VALID_LABELS:
        label = "unknown"
    record["label"] = label

    record["url"] = url
    return record


# ---------------------------------------------------------------------------
# A) JSON dataset loader
# ---------------------------------------------------------------------------

def load_json_dataset(path: str | Path, source_tag: str | None = None) -> list[dict]:
    """
    Load a JSON file containing a list of request records.
    Returns a validated list of records.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(raw, list):
        raise ValueError(f"Expected a JSON array, got {type(raw)} in {path}")

    records = []
    skipped = 0
    for item in raw:
        if not isinstance(item, dict):
            skipped += 1
            continue
        if source_tag:
            item["source"] = source_tag
        record = validate_record(item)
        if record is None:
            skipped += 1
        else:
            records.append(record)

    print(f"  Loaded {len(records)} records from {path.name}  (skipped {skipped})")
    return records


def load_multiple_datasets(*paths: str | Path) -> list[dict]:
    """Load and merge multiple JSON dataset files."""
    all_records = []
    for p in paths:
        p = Path(p)
        if p.exists():
            all_records.extend(load_json_dataset(p, source_tag=p.stem))
        else:
            print(f"  [WARN] Not found, skipping: {p}")
    return all_records


# ---------------------------------------------------------------------------
# B) Raw HTTP parser (exported_requests.txt format)
# ---------------------------------------------------------------------------

def parse_raw_request(block: str, default_ip: str = "127.0.0.1") -> dict | None:
    """
    Parse a single raw HTTP request block into a standard record.

    Expected format:
        GET /api/users?id=1 HTTP/1.1
        Host: localhost
        User-Agent: TestClient
        Content-Type: application/json

        {"key": "value"}

    Returns a record dict or None if the block is unparseable.
    """
    block = block.strip()
    if not block:
        return None

    lines = block.splitlines()

    # --- Request line ---
    request_line = lines[0].strip()
    # Match:  METHOD  /path  HTTP/x.x
    match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/\S+)?$",
                     request_line, re.IGNORECASE)
    if not match:
        return None

    method = match.group(1).upper()
    url    = match.group(2)

    # --- Headers ---
    headers = {}
    body_start_idx = 1
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":          # blank line = end of headers
            body_start_idx = i + 1
            break
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    else:
        body_start_idx = len(lines)

    # --- Body ---
    body_lines = lines[body_start_idx:]
    body = "\n".join(body_lines).strip()

    # --- IP extraction from X-Forwarded-For or X-Real-IP headers ---
    ip = (headers.get("x-forwarded-for") or
          headers.get("x-real-ip") or
          headers.get("client-ip") or
          default_ip)

    return validate_record({
        "method":  method,
        "url":     url,
        "headers": headers,
        "body":    body,
        "ip":      ip,
        "label":   "unknown",   # raw HTTP is unlabeled by default
        "source":  "raw_http",
    })


def parse_raw_http_file(path: str | Path,
                        separator: str = "---",
                        default_ip: str = "127.0.0.1") -> list[dict]:
    """
    Parse a file containing multiple raw HTTP requests separated by `separator`.
    Returns a list of validated record dicts.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Raw HTTP file not found: {path}")

    content = path.read_text(encoding="utf-8", errors="ignore")

    # Split on the separator line
    blocks = re.split(rf"^{re.escape(separator)}\s*$", content, flags=re.MULTILINE)

    records = []
    skipped = 0
    for block in blocks:
        record = parse_raw_request(block.strip(), default_ip=default_ip)
        if record:
            records.append(record)
        else:
            skipped += 1

    print(f"  Parsed {len(records)} raw HTTP requests from {path.name}  (skipped {skipped})")
    return records


# ---------------------------------------------------------------------------
# C) Capture file loader  (exported_requests.json from your middleware)
# ---------------------------------------------------------------------------

def load_captured_requests(json_path: str | Path,
                            label: str = "unknown") -> list[dict]:
    """
    Load the exported_requests.json from your FastAPI capture middleware.
    The format differs slightly — body may be nested JSON string.
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Capture file not found: {path}")

    raw_list = json.loads(path.read_text())
    records = []

    for item in raw_list:
        # The capture stores the *outer* request (POST /api/v1/detect).
        # The actual API payload is in item["body"] as a JSON string.
        body_str = item.get("body", "")
        try:
            inner = json.loads(body_str)
            # Extract the inner request that was sent to the engine
            record = validate_record({
                "method":  inner.get("method", "GET"),
                "url":     inner.get("url", "/"),
                "headers": inner.get("headers", {}),
                "body":    inner.get("body", ""),
                "ip":      inner.get("ip_address", "127.0.0.1"),
                "label":   label,
                "source":  "captured",
            })
        except (json.JSONDecodeError, AttributeError):
            # Not a JSON body — treat the raw request itself
            record = validate_record({
                "method":  item.get("method", "GET"),
                "url":     item.get("url", "/"),
                "headers": item.get("headers", {}),
                "body":    body_str,
                "ip":      "127.0.0.1",
                "label":   label,
                "source":  "captured",
            })

        if record:
            records.append(record)

    print(f"  Loaded {len(records)} captured records from {path.name}")
    return records


# ---------------------------------------------------------------------------
# CLI usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, pprint

    if len(sys.argv) < 2:
        print("Usage: python parser.py <file.json|file.txt>")
        sys.exit(1)

    p = Path(sys.argv[1])
    if p.suffix == ".json":
        recs = load_json_dataset(p)
    else:
        recs = parse_raw_http_file(p)

    print(f"\nFirst 3 records:")
    for r in recs[:3]:
        pprint.pprint(r)
        print()
