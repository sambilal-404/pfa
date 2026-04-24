#!/usr/bin/env python3
"""
replay.py
---------
Replays captured traffic (from exported_requests.json or exported_requests.txt)
through the DetectionEngine to:
  1. Detect False Positives in real traffic
  2. Spot missed attacks in captured malicious sessions
  3. Profile detection latency

Usage:
  python scripts/replay.py --json captured/exported_requests.json
  python scripts/replay.py --raw  captured/exported_requests.txt
  python scripts/replay.py --json captured/exported_requests.json --label attack
"""

import sys
import json
import time
import argparse
from pathlib import Path
from collections import Counter

REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

try:
    from colorama import Fore, Style, init as cinit
    cinit(autoreset=True)
    RED = Fore.RED; GREEN = Fore.GREEN; YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN; RESET = Style.RESET_ALL; BOLD = Style.BRIGHT
except ImportError:
    RED = GREEN = YELLOW = CYAN = RESET = BOLD = ""

try:
    from src.engine.detector import DetectionEngine
    engine = DetectionEngine()
    print("[INFO] Using real DetectionEngine")
except ImportError:
    print("[WARN] Using MockDetectionEngine")
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from benchmark import MockDetectionEngine
    engine = MockDetectionEngine()

# Import parser utilities
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from parser import load_captured_requests, parse_raw_http_file, load_json_dataset


def replay(records: list[dict], verbose: bool = True) -> dict:
    """Run all records through the engine and collect stats."""
    decisions = Counter()
    latencies = []
    fp_examples = []
    fn_examples = []

    print(f"\n  Replaying {len(records)} requests...\n")

    for i, rec in enumerate(records):
        method  = rec.get("method",  "GET")
        url     = rec.get("url",     "/")
        headers = rec.get("headers", {})
        body    = rec.get("body",    "")
        ip      = rec.get("ip",      "127.0.0.1")
        label   = rec.get("label",   "unknown")

        t0 = time.perf_counter()
        result = engine.analyze(method, url, headers, body, ip)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed_ms)

        decision = result.recommendation
        decisions[decision] += 1

        # FP detection: legit request got blocked/flagged
        flagged = decision in ("BLOCK", "FLAG")
        if label == "legit" and flagged:
            fp_examples.append({"url": url, "decision": decision, "reason": result.reason})

        # FN detection: known attack was allowed
        if label == "attack" and not flagged:
            fn_examples.append({"url": url, "attack_type": rec.get("attack_type"), "reason": result.reason})

        if verbose:
            color = (RED if decision == "BLOCK"
                     else YELLOW if decision == "FLAG"
                     else GREEN)
            print(f"  [{i+1:04d}] {CYAN}{method:6}{RESET} {url[:55]:57}"
                  f"→ {color}{decision}{RESET}  ({elapsed_ms:.1f}ms)")

    return {
        "decisions": dict(decisions),
        "total": len(records),
        "latency_avg_ms": sum(latencies) / len(latencies) if latencies else 0,
        "latency_max_ms": max(latencies) if latencies else 0,
        "latency_min_ms": min(latencies) if latencies else 0,
        "fp_examples": fp_examples[:10],
        "fn_examples": fn_examples[:10],
    }


def print_replay_report(stats: dict):
    print(f"\n{BOLD}{'='*60}")
    print("  REPLAY REPORT")
    print(f"{'='*60}{RESET}")

    total = stats["total"]
    for decision, count in sorted(stats["decisions"].items()):
        pct = count / total * 100 if total else 0
        bar = "█" * int(pct / 2)
        color = RED if decision == "BLOCK" else YELLOW if decision == "FLAG" else GREEN
        print(f"  {decision:<8} {count:>5} ({pct:5.1f}%)  {color}{bar}{RESET}")

    print(f"\n  Latency:  avg={stats['latency_avg_ms']:.2f}ms  "
          f"min={stats['latency_min_ms']:.2f}ms  max={stats['latency_max_ms']:.2f}ms")

    if stats["fp_examples"]:
        print(f"\n{RED}  False Positives (legit → BLOCKED/FLAGGED):{RESET}")
        for ex in stats["fp_examples"]:
            print(f"    {ex['decision']:5} | {ex['url'][:60]}  → {ex['reason']}")

    if stats["fn_examples"]:
        print(f"\n{RED}  False Negatives (attacks → ALLOWED):{RESET}")
        for ex in stats["fn_examples"]:
            print(f"    {ex.get('attack_type','?'):20} | {ex['url'][:50]}")

    print()


def main():
    ap = argparse.ArgumentParser(description="Replay captured traffic through DetectionEngine")
    ap.add_argument("--json",    default=None, help="JSON file (exported_requests.json or dataset)")
    ap.add_argument("--raw",     default=None, help="Raw HTTP file (exported_requests.txt)")
    ap.add_argument("--label",   default="unknown",
                    choices=["legit","attack","unknown"],
                    help="Label to assign to all records")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--limit",   type=int, default=None)
    args = ap.parse_args()

    records = []

    if args.json:
        path = Path(args.json)
        # Try captured format first, then standard JSON
        try:
            records = load_captured_requests(path, label=args.label)
        except Exception:
            records = load_json_dataset(path)

    elif args.raw:
        records = parse_raw_http_file(Path(args.raw))
        for r in records:
            r["label"] = args.label
    else:
        print("Usage: python replay.py --json <file> or --raw <file>")
        sys.exit(1)

    if args.limit:
        records = records[:args.limit]

    if not records:
        print("No records to replay.")
        sys.exit(0)

    stats = replay(records, verbose=args.verbose)
    print_replay_report(stats)

    # Save
    out = REPO_ROOT / "replay_report.json"
    out.write_text(json.dumps(stats, indent=2, default=str))
    print(f"  Report saved → {out}\n")


if __name__ == "__main__":
    main()
