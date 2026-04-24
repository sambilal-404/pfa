# API Contract — PFA Detection Engine v1.0.0

## Base URL

```
http://<host>:8000/api/v1
```

Interactive docs: `http://<host>:8000/docs`

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/detect` | Analyze an HTTP request for threats |
| GET | `/api/v1/health` | Service health check |
| GET | `/api/v1/metrics` | Runtime counters |

---

## POST /api/v1/detect

### Request Body (JSON)

```json
{
  "method": "POST",
  "url": "/api/users?page=1",
  "headers": {
    "content-type": "application/json",
    "authorization": "Bearer eyJ..."
  },
  "body": "{\"username\": \"john\", \"password\": \"secret\"}",
  "ip_address": "192.168.1.100"
}
```

### Request Field Definitions

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `method` | string | No (default: `"GET"`) | One of: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS | HTTP method (normalized to uppercase) |
| `url` | string | **YES** | 1–8192 chars | Full URL path including query string (e.g., `/api/users?id=1`) |
| `headers` | object | No (default: `{}`) | Key-value strings | HTTP headers; keys are normalized to lowercase internally |
| `body` | string | No (default: `""`) | Max 1 MB (1 048 576 chars) | Raw request body as string |
| `ip_address` | string | **YES** | IPv4 or IPv6 | Client IP address |

#### Excluded headers (not inspected for signatures)
`user-agent`, `accept`, `accept-encoding`, `accept-language`, `connection`, `host`, `content-type`, `content-length`

---

### Response Body (JSON) — HTTP 200

```json
{
  "is_threat": true,
  "threat_level": "CRITICAL",
  "recommendation": "BLOCK",
  "reason": "Critical threat detected: SQL Union-Based Injection",
  "triggering_factor": "critical_signature",
  "matched_rules": [
    {
      "rule_id": "SQLI-001",
      "rule_name": "SQL Union-Based Injection",
      "severity": "CRITICAL",
      "attack_type": "SQL_INJECTION",
      "matched_field": "url",
      "matched_value": "UNION SELECT",
      "position": 23,
      "description": "Detects UNION-based SQL injection attempts"
    }
  ],
  "rate_limit_status": {
    "allowed": true,
    "current_count": 5,
    "remaining": 95,
    "reset_at": 1714000060.123,
    "limit": 100
  },
  "anomaly_scores": {
    "scores": {
      "url_length": {
        "feature_name": "url_length",
        "value": 85.0,
        "mean": 45.0,
        "std": 25.0,
        "z_score": 1.6,
        "is_anomaly": false,
        "threshold": 3.0
      },
      "body_length": {
        "feature_name": "body_length",
        "value": 0.0,
        "mean": 120.0,
        "std": 100.0,
        "z_score": -1.2,
        "is_anomaly": false,
        "threshold": 3.0
      },
      "query_param_count": {
        "feature_name": "query_param_count",
        "value": 1.0,
        "mean": 2.0,
        "std": 1.5,
        "z_score": -0.6667,
        "is_anomaly": false,
        "threshold": 3.0
      },
      "special_char_count": {
        "feature_name": "special_char_count",
        "value": 12.0,
        "mean": 8.0,
        "std": 6.0,
        "z_score": 0.6667,
        "is_anomaly": false,
        "threshold": 3.0
      },
      "entropy": {
        "feature_name": "entropy",
        "value": 3.9,
        "mean": 3.2,
        "std": 0.8,
        "z_score": 0.875,
        "is_anomaly": false,
        "threshold": 3.0
      }
    },
    "anomaly_count": 0,
    "is_anomalous": false,
    "max_z_score": 1.6
  },
  "features": {
    "url_length": 85.0,
    "body_length": 0.0,
    "query_param_count": 1.0,
    "special_char_count": 12.0,
    "entropy": 3.9,
    "header_count": 2.0,
    "numeric_char_ratio": 0.0235
  }
}
```

### Response Field Definitions

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `is_threat` | boolean | `true` / `false` | Whether the request is a threat |
| `threat_level` | string | `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Severity classification |
| `recommendation` | string | `ALLOW`, `FLAG`, `BLOCK` | Action to take |
| `reason` | string | free text | Human-readable explanation |
| `triggering_factor` | string | see below | Machine-readable trigger |
| `matched_rules` | array | see below | Signature matches (may be empty `[]`) |
| `rate_limit_status` | object | see below | Rate limit state for the IP |
| `anomaly_scores` | object | see below | Per-feature statistical analysis |
| `features` | object | 7 float values | Extracted numeric features |

#### `triggering_factor` values

| Value | Meaning |
|-------|---------|
| `"none"` | No threat — ALLOW |
| `"critical_signature"` | CRITICAL severity rule matched |
| `"rate_limit"` | IP exceeded rate limit |
| `"high_signature"` | HIGH severity rule matched |
| `"anomaly_score"` | Multiple anomalies or very high z-score |
| `"medium_signature"` | MEDIUM rule matched (with anomaly or repeated) |
| `"single_anomaly"` | One anomaly with high confidence |
| `"low_signature"` | LOW severity rule matched |

#### `threat_level` + `recommendation` combinations

| threat_level | recommendation | is_threat | When |
|-------------|---------------|-----------|------|
| SAFE | ALLOW | false | Clean request |
| LOW | FLAG | true | Low signals, needs review |
| MEDIUM | FLAG | true | Anomaly score triggered |
| HIGH | BLOCK | true | HIGH signature or rate limit |
| CRITICAL | BLOCK | true | CRITICAL signature matched |

#### `matched_rules[]` item

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | e.g., `"SQLI-001"`, `"XSS-001"` |
| `rule_name` | string | Human name |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `attack_type` | string | `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`, `PROTOCOL_ATTACK`, `UNKNOWN` |
| `matched_field` | string | `"url"`, `"body"`, or `"headers"` |
| `matched_value` | string | What was matched (truncated to 100 chars) |
| `position` | integer | Character offset where match starts |
| `description` | string | Rule description |

#### `rate_limit_status` object

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether the IP is under the limit |
| `current_count` | integer | Requests from this IP in current window |
| `remaining` | integer | Requests remaining before block |
| `reset_at` | float | Unix monotonic timestamp when window resets |
| `limit` | integer | Max requests per window (default: 100) |

#### `anomaly_scores` object

| Field | Type | Description |
|-------|------|-------------|
| `scores` | object | Map of feature_name → AnomalyScore |
| `anomaly_count` | integer | Number of features flagged as anomalous |
| `is_anomalous` | boolean | Any feature anomalous? |
| `max_z_score` | float | Highest z-score across all features |

#### `features` object (7 fixed keys, all float)

| Key | Description | Baseline mean | Baseline std |
|-----|-------------|--------------|-------------|
| `url_length` | Length of URL string | 45.0 | 25.0 |
| `body_length` | Length of body string | 120.0 | 100.0 |
| `query_param_count` | Number of query parameters | 2.0 | 1.5 |
| `special_char_count` | Count of special chars in url+body | 8.0 | 6.0 |
| `entropy` | Shannon entropy of url+body | 3.2 | 0.8 |
| `header_count` | Number of headers | — (not anomaly-checked) | — |
| `numeric_char_ratio` | Ratio of digit chars in url+body | — (not anomaly-checked) | — |

> Note: `header_count` and `numeric_char_ratio` are in `features` but are NOT included in anomaly scoring.

---

### Decision Pipeline (Priority Order)

```
1. CRITICAL signature match    → BLOCK  (threat_level: CRITICAL)
2. Rate limit exceeded         → BLOCK  (threat_level: HIGH)
3. HIGH signature match        → BLOCK  (threat_level: HIGH)
4. anomaly_count ≥ 3 OR max_z_score ≥ 4.5  → FLAG  (threat_level: MEDIUM)
5. MEDIUM signature + anomaly  → FLAG  (threat_level: LOW)
6. Single anomaly + confidence ≥ 3.5  → FLAG  (threat_level: LOW)
7. LOW signature alone         → FLAG  (threat_level: LOW)
8. None of above               → ALLOW (threat_level: SAFE)
```

---

### Error Responses

| Status | Body | When |
|--------|------|------|
| 422 | `{"detail": "Invalid request payload or headers."}` | Missing required fields or invalid format |
| 500 | `{"detail": "Internal error during analysis"}` | Unexpected engine error |

---

## GET /api/v1/health

### Response (HTTP 200)

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "signature_engine": "healthy",
    "rate_limiter": "healthy",
    "anomaly_detector": "healthy",
    "decision_engine": "healthy"
  }
}
```

---

## GET /api/v1/metrics

### Response (HTTP 200)

```json
{
  "metrics": {
    "requests_total": 1543,
    "decisions_total": 1543,
    "decision_allow": 1200,
    "decision_flag": 280,
    "decision_block": 63,
    "signature_matches": 90,
    "anomaly_detections": 310,
    "rate_limit_blocks": 12
  }
}
```

---

## Signature Rules Reference

| Rule ID | Name | Severity | Attack Type | Targets |
|---------|------|----------|-------------|---------|
| SQLI-001 | SQL Union-Based Injection | CRITICAL | SQL_INJECTION | url, body |
| SQLI-002 | SQL Tautology (OR 1=1) | CRITICAL | SQL_INJECTION | url, body |
| SQLI-003 | SQL Comment-Based Injection | HIGH | SQL_INJECTION | url, body |
| SQLI-004 | SQL DML Statement | MEDIUM | SQL_INJECTION | url, body |
| SQLI-005 | SQL String Termination | CRITICAL | SQL_INJECTION | url, body |
| SQLI-006 | SQL Function Injection | HIGH | SQL_INJECTION | url, body |
| XSS-001 | Script Tag Injection | CRITICAL | XSS | url, body, headers |
| XSS-002 | Event Handler Injection | HIGH | XSS | url, body, headers |
| XSS-003 | JavaScript Protocol | HIGH | XSS | url, body, headers |
| XSS-004 | HTML Entity XSS | MEDIUM | XSS | url, body, headers |
| XSS-005 | DOM Source Injection | HIGH | XSS | url, body |
| PT-001 | Directory Traversal (Basic) | HIGH | PATH_TRAVERSAL | url only |
| PT-002 | Path Traversal (Encoded) | HIGH | PATH_TRAVERSAL | url only |
| PT-003 | Path Traversal (Double Encoding) | HIGH | PATH_TRAVERSAL | url only |
| PT-004 | Sensitive File Access | CRITICAL | PATH_TRAVERSAL | url only |
| CMDI-001 | Unix Command Injection | CRITICAL | COMMAND_INJECTION | url, body |
| CMDI-002 | Command Pipe Injection | CRITICAL | COMMAND_INJECTION | url, body |
| CMDI-003 | Command Substitution | HIGH | COMMAND_INJECTION | url, body |
| CMDI-004 | Logical Operator Injection | HIGH | COMMAND_INJECTION | url, body |
| CMDI-005 | Windows Command Injection | HIGH | COMMAND_INJECTION | url, body |
| PROTO-001 | SSRF Pattern | HIGH | PROTOCOL_ATTACK | url, body, headers |
| PROTO-002 | Log4j JNDI Pattern | CRITICAL | PROTOCOL_ATTACK | url, body, headers |

---

## Rate Limit Defaults

| Parameter | Default | Env Variable |
|-----------|---------|-------------|
| Max requests per window | 100 | `PFA_RATE_LIMIT_MAX_REQUESTS` |
| Window duration | 60 seconds | `PFA_RATE_LIMIT_WINDOW_SECONDS` |
| Cleanup interval | 300 seconds | `PFA_RATE_LIMIT_CLEANUP_INTERVAL` |
| Sigma threshold | 3.0 | `PFA_ANOMALY_SIGMA_THRESHOLD` |
| Multiple anomaly threshold | 3 | `PFA_ANOMALY_MULTIPLE_THRESHOLD` |
