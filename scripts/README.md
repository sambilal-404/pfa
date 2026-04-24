# WAF Evaluation System — Complete Guide

## Project Structure

```
waf-eval/
├── datasets/
│   ├── raw/                      ← Raw payload .txt files (one payload per line)
│   │   ├── sqli_generic.txt      ← SQL injection payloads (from PayloadsAllTheThings)
│   │   ├── xss_basic.txt         ← XSS payloads
│   │   ├── path_traversal.txt    ← Path traversal payloads (from SecLists/FuzzDB)
│   │   └── cmdi.txt              ← Command injection payloads (from FuzzDB)
│   └── processed/                ← Structured JSON datasets (ready for benchmark)
│       ├── legit.json            ← ~60 realistic legitimate API requests
│       ├── malicious.json        ← Attack requests built from raw payloads
│       ├── owasp.json            ← Optional: OWASP-specific dataset
│       └── captured.json         ← Optional: traffic from your exported_requests.json
├── scripts/
│   ├── collect_datasets.py       ← Step 1: Download payloads + generate datasets
│   ├── parser.py                 ← Load JSON or raw HTTP files into standard records
│   ├── generator.py              ← Convert raw payloads → structured HTTP requests
│   ├── benchmark.py              ← Step 2: Full evaluation with metrics
│   └── replay.py                 ← Step 3: Replay captured traffic
└── benchmark_report.json         ← Generated output after running benchmark.py
```

---

## Standard Data Format

Every request in every dataset follows this schema:

```json
{
  "method":      "GET",
  "url":         "/api/users?id=1' OR '1'='1",
  "headers":     {"User-Agent": "Mozilla/5.0"},
  "body":        "",
  "ip":          "10.0.0.1",
  "label":       "attack",
  "attack_type": "SQL Injection",
  "raw_payload": "1' OR '1'='1",
  "source":      "sqli_generic"
}
```

| Field | Why it exists |
|-------|--------------|
| `method` | HTTP verb — GET/POST/PUT/DELETE etc. Different methods hit different code paths |
| `url` | Full URL with query params — this is where most injections land |
| `headers` | HTTP headers — XSS can hide in `User-Agent`, Log4Shell in `X-Api-Version` |
| `body` | Request body — POST-based SQLi, JSON XSS payloads |
| `ip` | Source IP — needed by the rate limiter |
| `label` | `"legit"` or `"attack"` — ground truth for metrics calculation |
| `attack_type` | Category for per-type recall breakdown (SQLi vs XSS vs Path Traversal) |
| `raw_payload` | The original payload string — useful for debugging false negatives |
| `source` | Which file/source this came from — traceability |

---

## Step-by-Step Commands

### Step 1 — Collect datasets

```bash
# Downloads OWASP/FuzzDB payloads (or uses built-in fallbacks if GitHub blocked)
# Generates legit.json and malicious.json
python scripts/collect_datasets.py
```

Expected output:
```
[1/3] Downloading attack payload lists...
  Saved 200+ payloads → datasets/raw/sqli_generic.txt
  Saved 100+ payloads → datasets/raw/xss_basic.txt
  ...
[2/3] Generating legitimate traffic dataset...
  Generated 60 legit records → datasets/processed/legit.json
[3/3] Building attack dataset from payloads...
  Built 120+ attack records → datasets/processed/malicious.json
✅ Done.
```

### Step 2 — Download manually (if GitHub access works)

```bash
# OWASP PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git datasets/PayloadsAllTheThings

# FuzzDB
git clone https://github.com/fuzzdb-project/fuzzdb.git datasets/fuzzdb

# SecLists
git clone https://github.com/danielmiessler/SecLists.git datasets/SecLists

# Then generate structured datasets from raw files:
python scripts/generator.py \
  --input datasets/PayloadsAllTheThings/SQL\ Injection/Intruder/Auth_Bypass.txt \
  --attack-type "SQL Injection" \
  --output datasets/processed/sqli_authbypass.json

python scripts/generator.py \
  --input datasets/fuzzdb/attack/os-cmd-execution/command-injection-template.txt \
  --attack-type "Command Injection" \
  --output datasets/processed/cmdi_fuzzdb.json
```

### Step 3 — Run full benchmark

```bash
# Basic run (shows summary only)
python scripts/benchmark.py

# Verbose (shows every request)
python scripts/benchmark.py --verbose

# Test specific layer only
python scripts/benchmark.py --layer signature
python scripts/benchmark.py --layer rate
python scripts/benchmark.py --layer anomaly

# Use a custom dataset
python scripts/benchmark.py --input datasets/processed/sqli.json --verbose

# Limit records for quick testing
python scripts/benchmark.py --limit 20 --verbose
```

### Step 4 — Replay your captured traffic

```bash
# Replay exported_requests.json (from your FastAPI middleware)
python scripts/replay.py --json path/to/exported_requests.json --label legit

# Replay raw HTTP file
python scripts/replay.py --raw path/to/exported_requests.txt --verbose

# Find false positives in real traffic
python scripts/replay.py --json exported_requests.json --label legit --verbose
```

### Step 5 — Parse raw HTTP files manually

```bash
python scripts/parser.py exported_requests.txt
python scripts/parser.py datasets/processed/legit.json
```

---

## Understanding the Metrics

| Metric | Formula | What it means |
|--------|---------|----------------|
| **TP** | attacks → BLOCK/FLAG | Attacks you caught ✓ |
| **TN** | legit → ALLOW | Legit traffic you let through ✓ |
| **FP** | legit → BLOCK/FLAG | False alarms — real users blocked ✗ |
| **FN** | attacks → ALLOW | Missed attacks ✗ |
| **Precision** | TP / (TP + FP) | Of all blocks, how many were real attacks? |
| **Recall** | TP / (TP + FN) | Of all attacks, how many did you catch? |
| **FPR** | FP / (FP + TN) | % of legit traffic falsely blocked |
| **F1** | 2·P·R / (P+R) | Harmonic mean — overall balance |

**Target values:**
- FPR < 10% (current WAFs: ~40%)
- Recall > 90%
- F1 > 85%

---

## Testing Each Layer

### Signature layer only
```bash
python scripts/benchmark.py --layer signature
```
Checks: Does SQLi regex fire? Does legit traffic pass?

### Rate limiter only
```bash
python scripts/benchmark.py --layer rate
```
Checks: Does the 21st request from same IP get blocked?

### Anomaly detection only
```bash
python scripts/benchmark.py --layer anomaly
```
Checks: Does a 500-char URL get flagged? Does a normal request pass?

---

## How to Detect False Positives

A False Positive = a legitimate request gets BLOCK or FLAG.

```bash
# Run legit traffic only, check for anything that isn't ALLOW
python scripts/replay.py --json datasets/processed/legit.json --label legit --verbose
```

Look for lines where a legit request gets BLOCK/FLAG. The `reason` field tells you exactly which rule triggered. Add that URL pattern to your header exclusion list or tune the regex.

## How to Detect False Negatives

A False Negative = an attack request gets ALLOW.

```bash
# Run only attack traffic, look for ALLOW decisions
python scripts/benchmark.py --input datasets/processed/malicious.json --verbose 2>&1 | grep "ALLOW"
```

Each missed attack shows the payload. Use that to write a new signature rule.

---

## Connecting to the ML Classifier

When your benchmark runs, each request generates a `features` dict:

```python
{
  "url_length": 150.0,
  "body_length": 0.0,
  "query_param_count": 1.0,
  "special_char_count": 12.0,
  "entropy": 4.1,
  "header_count": 2.0,
  "numeric_char_ratio": 0.08
}
```

The benchmark saves all of these to `benchmark_report.json`. Hamza's ML classifier
can load that file and train on `(features, label)` pairs to improve recall on
the FN cases your rule-based engine misses.

```python
import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

report = json.load(open("benchmark_report.json"))
logs = report["logs"]

X = pd.DataFrame([log.get("features", {}) for log in logs])
y = [1 if log["label"] == "attack" else 0 for log in logs]

clf = RandomForestClassifier()
clf.fit(X, y)
```
