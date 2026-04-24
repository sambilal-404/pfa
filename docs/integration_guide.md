# Integration Guide — PFA Detection Engine

## System Architecture

```
[Mouad: Fuzzer] ──POST /api/v1/detect──► [Detection Engine (Bilal)]
                                                │
                                         recommendation
                                         features vector
                                                │
                               ┌────────────────┴───────────────┐
                               ▼                                 ▼
                    [Hamza: ML Classifier]           [Ayoub: Backend + DB]
                    (uses features + label)          (stores result, drives UI)
```

---

## Quick Start — Run the Service

```bash
cd pfa-detection-engine
pip install -r requirements.txt
uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Service is ready when you see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Health check:
```bash
curl http://localhost:8000/api/v1/health
```

---

## Environment Variables (optional overrides)

| Variable | Default | Effect |
|----------|---------|--------|
| `PFA_RATE_LIMIT_MAX_REQUESTS` | `100` | Requests per window before blocking |
| `PFA_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window duration |
| `PFA_ANOMALY_SIGMA_THRESHOLD` | `3.0` | Z-score threshold for anomaly |
| `PFA_ANOMALY_MULTIPLE_THRESHOLD` | `3` | How many anomalous features trigger FLAG |
| `PFA_ANOMALY_ENABLE_DETECTION` | `true` | Toggle anomaly detection |
| `PFA_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Section A — Ayoub (Backend + Dashboard)

### What you receive from the detection engine

Every call to `POST /api/v1/detect` returns a structured JSON object. Here is the exact schema you must store:

```json
{
  "is_threat":        true,
  "threat_level":     "CRITICAL",
  "recommendation":   "BLOCK",
  "reason":           "Critical threat detected: SQL Union-Based Injection",
  "triggering_factor":"critical_signature",
  "matched_rules": [
    {
      "rule_id":       "SQLI-001",
      "rule_name":     "SQL Union-Based Injection",
      "severity":      "CRITICAL",
      "attack_type":   "SQL_INJECTION",
      "matched_field": "url",
      "matched_value": "UNION SELECT",
      "position":      23,
      "description":   "Detects UNION-based SQL injection attempts"
    }
  ],
  "rate_limit_status": {
    "allowed":       true,
    "current_count": 5,
    "remaining":     95,
    "reset_at":      1714000060.123,
    "limit":         100
  },
  "anomaly_scores": {
    "scores": {
      "url_length":         { "value": 85.0, "z_score": 1.6, "is_anomaly": false, "threshold": 3.0, "mean": 45.0, "std": 25.0, "feature_name": "url_length" },
      "body_length":        { "value": 0.0,  "z_score": -1.2, "is_anomaly": false, "threshold": 3.0, "mean": 120.0, "std": 100.0, "feature_name": "body_length" },
      "query_param_count":  { "value": 1.0,  "z_score": -0.67, "is_anomaly": false, "threshold": 3.0, "mean": 2.0, "std": 1.5, "feature_name": "query_param_count" },
      "special_char_count": { "value": 12.0, "z_score": 0.67,  "is_anomaly": false, "threshold": 3.0, "mean": 8.0, "std": 6.0, "feature_name": "special_char_count" },
      "entropy":            { "value": 3.9,  "z_score": 0.875, "is_anomaly": false, "threshold": 3.0, "mean": 3.2, "std": 0.8, "feature_name": "entropy" }
    },
    "anomaly_count": 0,
    "is_anomalous":  false,
    "max_z_score":   1.6
  },
  "features": {
    "url_length":        85.0,
    "body_length":       0.0,
    "query_param_count": 1.0,
    "special_char_count":12.0,
    "entropy":           3.9,
    "header_count":      2.0,
    "numeric_char_ratio":0.0235
  }
}
```

### Suggested DB schema (columns to store per detection event)

```sql
CREATE TABLE detection_events (
    id               SERIAL PRIMARY KEY,
    created_at       TIMESTAMP DEFAULT NOW(),
    -- request info
    req_method       VARCHAR(10),
    req_url          TEXT,
    req_ip           VARCHAR(45),
    -- decision
    is_threat        BOOLEAN,
    threat_level     VARCHAR(10),  -- SAFE/LOW/MEDIUM/HIGH/CRITICAL
    recommendation   VARCHAR(10),  -- ALLOW/FLAG/BLOCK
    reason           TEXT,
    triggering_factor VARCHAR(30),
    -- anomaly summary
    anomaly_count    INTEGER,
    is_anomalous     BOOLEAN,
    max_z_score      FLOAT,
    -- rate limit
    rate_limit_allowed   BOOLEAN,
    rate_limit_remaining INTEGER,
    -- matched rules (store as JSON or in separate table)
    matched_rules    JSONB,
    features         JSONB,
    anomaly_scores   JSONB
);
```

### Integration workflow

```
1. User request arrives at your backend
2. Forward the request to detection engine:
   POST http://detection-engine:8000/api/v1/detect
   Body: { method, url, headers, body, ip_address }

3. Receive detection response (JSON above)

4. Branch on `recommendation`:
   - "ALLOW"  → pass request through to your API logic
   - "FLAG"   → pass through BUT log + alert + send to Hamza's classifier
   - "BLOCK"  → reject immediately, return 403 to client

5. Store full detection response in DB (detection_events table)

6. Dashboard reads from DB to display:
   - threat counts per type
   - blocked IPs
   - attack timelines
   - anomaly trends
```

### Python integration snippet

```python
import httpx

DETECTION_ENGINE_URL = "http://localhost:8000/api/v1/detect"

async def check_request(method, url, headers, body, client_ip):
    payload = {
        "method": method,
        "url": url,
        "headers": dict(headers),
        "body": body or "",
        "ip_address": client_ip,
    }
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.post(DETECTION_ENGINE_URL, json=payload)
        resp.raise_for_status()
        return resp.json()

# Usage
result = await check_request("POST", "/api/login", req.headers, req.body, req.client.host)
if result["recommendation"] == "BLOCK":
    return JSONResponse({"error": "Forbidden"}, status_code=403)
```

### Potential breaking issues for Ayoub

1. **`reset_at` is a monotonic float, not a Unix epoch timestamp.** Do not display it as a human date. It is only useful for "seconds until reset" (`reset_at - time.monotonic()`). Store it as raw float or discard it from the DB.
2. **`matched_rules` can be an empty list `[]`** even when `is_threat=true` (anomaly-only detections). Always check `is_threat`, not `len(matched_rules) > 0`.
3. **`ip_address` validation is strict** — must be a valid IPv4 or IPv6 address. If you forward X-Forwarded-For headers, validate them before sending. The engine will return 422 on invalid IPs.
4. **Rate limit is per-IP and in-memory.** If the detection engine restarts, counters reset. Plan for this in your dashboards.
5. **`body` must be a string, not an object.** If the original request body is JSON, serialize it: `json.dumps(body_dict)`.

---

## Section B — Hamza (ML Classifier)

### Feature vector format

The detection engine provides a 7-dimensional feature vector in every response under the `features` key:

```json
{
  "url_length":         85.0,
  "body_length":        0.0,
  "query_param_count":  1.0,
  "special_char_count": 12.0,
  "entropy":            3.9,
  "header_count":       2.0,
  "numeric_char_ratio": 0.0235
}
```

All values are `float`. The order for numpy/sklearn is:

```python
FEATURE_ORDER = [
    "url_length",
    "body_length",
    "query_param_count",
    "special_char_count",
    "entropy",
    "header_count",
    "numeric_char_ratio",
]

def response_to_vector(detection_response: dict) -> list[float]:
    f = detection_response["features"]
    return [f[k] for k in FEATURE_ORDER]
```

### Labels for classification

The detection engine provides `is_threat` (binary) and `threat_level` (multi-class):

| Label field | Values | Use for |
|-------------|--------|---------|
| `is_threat` | `true` / `false` | Binary classifier |
| `threat_level` | SAFE, LOW, MEDIUM, HIGH, CRITICAL | Multi-class classifier |
| `matched_rules[].attack_type` | SQL_INJECTION, XSS, PATH_TRAVERSAL, COMMAND_INJECTION, PROTOCOL_ATTACK | Attack type classifier |

**Recommended label mapping for binary:**
```python
label = 1 if response["is_threat"] else 0
```

**Recommended label mapping for multi-class attack type:**
```python
ATTACK_LABELS = {
    "SQL_INJECTION":    0,
    "XSS":             1,
    "PATH_TRAVERSAL":  2,
    "COMMAND_INJECTION":3,
    "PROTOCOL_ATTACK": 4,
    "NONE":            5,  # for legit traffic
}
attack_type = (
    response["matched_rules"][0]["attack_type"]
    if response["matched_rules"]
    else "NONE"
)
label = ATTACK_LABELS[attack_type]
```

### Using the datasets

#### `datasets/processed/legit.json`
- ~782 entries
- Schema: `{method, url, headers, body, ip, label, attack_type}`
- Field `ip` maps to `ip_address` in detection request
- `attack_type` is always `null`
- Use as negative class (label=0)

#### `datasets/processed/malicious.json`
- ~12 110 entries
- Same schema + additional `raw_payload` field (original attack string)
- `attack_type`: "Path Traversal", "SQL Injection", "XSS", "Command Injection"
- Use as positive class (label=1)

**WARNING — Field name mismatch:** The datasets use `"ip"` but the API requires `"ip_address"`. When feeding datasets through the API, rename the field:
```python
request_payload = {
    "method": entry["method"],
    "url": entry["url"],
    "headers": entry["headers"],
    "body": entry["body"],
    "ip_address": entry["ip"],  # rename "ip" → "ip_address"
}
```

### Using benchmark_report.json

The benchmark was run on 98 samples (60 legit, 38 attacks). Key metrics:

| Metric | Value | Meaning |
|--------|-------|---------|
| Precision | 0.931 | 93.1% of BLOCKs are real threats |
| Recall | 0.711 | Engine catches 71% of attacks |
| F1 | 0.806 | Balanced score |
| FPR | 0.033 | 3.3% false positive rate |

**Per attack type recall:**
- XSS: 90% (9/10)
- Path Traversal: 75% (6/8)
- Command Injection: 62.5% (5/8)
- SQL Injection: 58.3% (7/12)

**For Hamza:** The detection engine's `FLAG` decisions (cases it's unsure about) are the most valuable training signal for your ML model. Use those as hard examples. The engine misses ~29% of attacks — your classifier should focus on catching those.

### Building a training dataset via the API

```python
import json, httpx

def build_ml_dataset(entries: list, label: int) -> list[dict]:
    rows = []
    with httpx.Client() as client:
        for entry in entries:
            resp = client.post("http://localhost:8000/api/v1/detect", json={
                "method": entry["method"],
                "url": entry["url"],
                "headers": entry.get("headers", {}),
                "body": entry.get("body", ""),
                "ip_address": entry["ip"],
            })
            data = resp.json()
            rows.append({
                "features": data["features"],
                "anomaly_scores": {k: v["z_score"] for k, v in data["anomaly_scores"]["scores"].items()},
                "has_signature_match": len(data["matched_rules"]) > 0,
                "max_z_score": data["anomaly_scores"]["max_z_score"],
                "label": label,
                "attack_type": entry.get("attack_type"),
            })
    return rows
```

### Missing ML-ready improvements (known gaps)

1. **No timestamp feature** — time-of-day patterns not captured
2. **No per-IP history** — sequential request features not available
3. **Baselines are hardcoded** — anomaly detector uses fixed means/stds, not learned from real traffic. Update baselines via `engine.anomaly_detector.update_baseline()`.
4. **No confidence score** — only binary `is_threat`. Use `max_z_score` + `len(matched_rules)` as a proxy confidence.
5. **`header_count` and `numeric_char_ratio` are not anomaly-checked** — only 5 of 7 features are used in the anomaly detector.

---

## Section C — Mouad (Fuzzer)

### How to send requests to /detect

The endpoint is `POST http://localhost:8000/api/v1/detect`.

Every fuzzed request must be wrapped in this envelope:

```json
{
  "method": "<HTTP_METHOD>",
  "url": "<PATH_AND_QUERY_STRING>",
  "headers": { "<key>": "<value>" },
  "body": "<raw_body_string>",
  "ip_address": "<IPv4_or_IPv6>"
}
```

### Minimal curl commands

**Legitimate request:**
```bash
curl -s -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/users?page=1",
    "headers": {"content-type": "application/json"},
    "body": "",
    "ip_address": "192.168.1.100"
  }' | python3 -m json.tool
```

**SQL injection (should → BLOCK):**
```bash
curl -s -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/users?id=1 UNION SELECT NULL,NULL--",
    "headers": {},
    "body": "",
    "ip_address": "10.0.0.1"
  }' | python3 -m json.tool
```

**XSS (should → BLOCK):**
```bash
curl -s -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "/api/feedback",
    "headers": {},
    "body": "{\"comment\": \"<script>alert(1)</script>\"}",
    "ip_address": "10.0.0.2"
  }' | python3 -m json.tool
```

**Path traversal (should → BLOCK):**
```bash
curl -s -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/files?path=../../../etc/passwd",
    "headers": {},
    "body": "",
    "ip_address": "10.0.0.3"
  }' | python3 -m json.tool
```

**Command injection (should → BLOCK):**
```bash
curl -s -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "/api/ping?host=; cat /etc/passwd",
    "headers": {},
    "body": "",
    "ip_address": "10.0.0.4"
  }' | python3 -m json.tool
```

**Rate limit test (send 101+ times from same IP → 101st should → BLOCK):**
```bash
for i in $(seq 1 105); do
  curl -s -X POST http://localhost:8000/api/v1/detect \
    -H "Content-Type: application/json" \
    -d "{\"method\":\"GET\",\"url\":\"/api/test\",\"headers\":{},\"body\":\"\",\"ip_address\":\"10.1.1.1\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'#{$i}: {d[\"recommendation\"]} | remaining={d[\"rate_limit_status\"][\"remaining\"]}')"
done
```

### Validating detection accuracy

For each fuzzed payload, check the response fields:

```python
def validate_detection(response: dict, expected_block: bool) -> dict:
    actual_block = response["recommendation"] in ("BLOCK", "FLAG")
    return {
        "correct": actual_block == expected_block,
        "recommendation": response["recommendation"],
        "threat_level": response["threat_level"],
        "triggering_factor": response["triggering_factor"],
        "matched_rules": [r["rule_id"] for r in response["matched_rules"]],
        "is_anomalous": response["anomaly_scores"]["is_anomalous"],
    }
```

### Fields to fuzz

| Target field | Inject into | Notes |
|-------------|-------------|-------|
| SQL payloads | `url` query params, `body` | PUT in `?param=PAYLOAD` |
| XSS payloads | `url` query params, `body` | Also test `headers` (non-excluded ones) |
| Path traversal | `url` path or query | Engine checks `url` field only for PT rules |
| Command injection | `url`, `body` | Use semicolons, pipes, backticks |
| Log4j JNDI | `url`, `body`, `headers` | `${jndi:ldap://...}` |
| Rate limit | Fixed `ip_address`, many requests | Same IP, >100 req/60s |

### Known detection gaps (from benchmark)

These specific patterns are NOT currently detected — useful for your fuzzing targets:

| Pattern | Why missed |
|---------|-----------|
| `1 AND 1=1` (no quotes) | SQLI-002 requires quotes around values |
| `admin'--` (trailing comment) | SQLI-003 requires `--\s*$` at end of full field |
| `' OR EXISTS(SELECT ...)` | EXISTS-based blind injection not covered |
| `| cat /etc/passwd` (pipe + space before cat) | CMDI-002 requires `\b` after command name |
| `&& cat /etc/shadow` (double ampersand with space) | Same gap |
| `..%2F..%2F..%2Fetc%2Fpasswd` (percent-encoded) | Pattern expects `..%2f` without leading dots |
| `1 OR 1=1#` (hash comment, URL-encoded) | Hash is URL-decoded; pattern anchored to end |

### Python batch fuzzer example

```python
import httpx, json

PAYLOADS = [
    # (url, body, expected_recommendation)
    ("/api/users?id=1 UNION SELECT NULL--", "", "BLOCK"),
    ("/api/users?id=1 AND 1=1", "", "ALLOW"),   # known gap
    ("/api/files?path=../../../etc/passwd", "", "BLOCK"),
    ("/api/ping?host=; ls -la", "", "BLOCK"),
    ("/api/search?q=<script>alert(1)</script>", "", "BLOCK"),
]

with httpx.Client() as client:
    for url, body, expected in PAYLOADS:
        resp = client.post("http://localhost:8000/api/v1/detect", json={
            "method": "GET", "url": url,
            "headers": {}, "body": body,
            "ip_address": "10.0.0.99"
        })
        r = resp.json()
        status = "OK" if r["recommendation"] == expected else "MISS"
        print(f"[{status}] {url[:60]} → {r['recommendation']} (expected {expected})")
```
