# PFA - API Security Detection Engine

## Overview
Detection engine for REST APIs combining:
- Pattern Matching (Regex)
- Rate Limiting (Sliding Window)
- Anomaly Detection

## Features
- SQL Injection, XSS, Path Traversal detection
- Sliding window rate limiting
- Statistical anomaly detection (entropy, 3-sigma)
- Metrics collection

## Run
```bash
uvicorn src.api.app:app --reload
