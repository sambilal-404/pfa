# Detection Engine & Decision Logic (`detector.py` & `decision_engine.py`)

## Purpose of the files
These files act as the "Brain" of your project. `detector.py` orchestrates the flow of data through all three layers (Regex -> Rate Limit -> Anomaly). `decision_engine.py` looks at the results from all three layers and makes the final choice: `ALLOW`, `FLAG`, or `BLOCK`.

## Step-by-Step Explanation (`detector.py`)
1. **Initialization:** The `DetectionEngine` instantiates the `SignatureEngine`, `SlidingWindowRateLimiter`, `FeatureExtractor`, `AnomalyDetector`, and `DecisionEngine`.
2. **Pipeline Execution:** When `analyze()` is called, it:
   - Step 1: Passes data to `signature_engine`.
   - Step 2: Checks the IP with `rate_limiter`.
   - Step 3: Extracts numeric data using `feature_extractor`.
   - Step 4: Checks for statistical outliers with `anomaly_detector`.
3. **Final Decision:** It passes ALL these results into `decision_engine.decide()`.
4. **JSON Formatting:** It wraps everything into a `DetectionResult` object that can be easily converted to a dictionary (`to_dict()`) for the API response.

## Step-by-Step Explanation (`decision_engine.py`)
This file implements a strict priority chain to drastically lower False Positives:
1. **Critical Signature** -> Immediate `BLOCK` (e.g., SQLi DROP TABLE).
2. **Rate Limit Exceeded** -> Immediate `BLOCK`.
3. **High Signature** -> Immediate `BLOCK` (e.g., basic XSS).
4. **Multiple Anomalies (>=3)** -> `FLAG` (Send to ML).
5. **Medium Signature** -> `FLAG`.
6. **Single Anomaly** -> `FLAG`.
7. **Otherwise** -> `ALLOW`.

## Important Functions & Classes
- `DetectionResult` (in `detector.py`): Contains the boolean `is_threat`, the string `threat_level`, and the `recommendation` (ALLOW/FLAG/BLOCK).
- `DecisionEngine.decide()`: Counts the severity of the matched rules (`severity_counts`) and evaluates the strict `if/elif` chain.

## Real Examples from My Code
If a request triggers a Medium signature (like a suspicious Javascript protocol) AND a single anomaly (URL too long):
- The `decide()` method hits rule 5 (`MEDIUM signature match -> FLAG`) before it even gets to rule 6. It returns `FLAG` with a `LOW` threat level. It does NOT block it, saving a potential user from a false positive.

## Key Decisions & Why They Matter
1. **Separation of Concerns:** By splitting the orchestrator (`detector.py`) from the decision logic (`decision_engine.py`), your code is extremely clean.
2. **The FLAG Concept:** Blocking on a single statistical anomaly would cause massive False Positives. By returning `FLAG` instead, you perfectly bridge the gap between your engine and the upcoming Machine Learning classifier.
