# Anomaly Detector (`anomaly_detector.py`)

## Purpose of the file
This file implements the **Anomaly Detection** layer (Layer 3). While regex blocks *known* attacks, this layer flags *unknown/zero-day* attacks by finding statistical deviations from normal API traffic patterns.

## Step-by-Step Explanation
1. **Baselines:** The `AnomalyConfig` defines "normal" behavior (mean and standard deviation) for metrics like `url_length`, `body_length`, and `entropy`.
2. **Feature Extraction:** Although located in a separate file (`feature_extractor.py`), the request is first broken down into numeric values (e.g., URL length = 45, Entropy = 3.2).
3. **Z-Score Calculation:** For each feature, the detector calculates how many standard deviations the value is from the mean.
   Formula: `z_score = (value - mean) / std`
4. **3-Sigma Rule:** If the absolute value of the `z_score` is greater than the `sigma_threshold` (usually 3.0), the feature is flagged as an anomaly.
5. **Reporting:** It compiles an `AnomalyReport` containing all the features, their Z-scores, and a total count of anomalous features.

## Important Functions & Classes
- `_calculate_z_score(value, mean, std)`: The mathematical core. It includes a fail-safe: if `std <= 0` (meaning normal traffic never varies), any deviation is treated as an infinite anomaly.
- `AnomalyDetector.analyze()`: Loops over the `ANALYSIS_FEATURES` (like `url_length`, `entropy`) and applies the 3-sigma math to each.
- `AnomalyScore`: A dataclass recording the exact math for a single feature so you can explain exactly *why* it was flagged in logs.

## Real Examples from My Code
If your baseline for URL length is `mean: 45.0` and `std: 25.0`:
- A normal request: Length = 50. `Z = (50 - 45) / 25 = 0.2`. Not an anomaly.
- A Path Traversal attack: Length = 200. `Z = (200 - 45) / 25 = 6.2`. Since `6.2 > 3.0` (your sigma threshold), `is_anomaly = True`.

## Key Decisions & Why They Matter
1. **The 3-Sigma Rule:** Statistically, 99.7% of normal data falls within 3 standard deviations. By setting the threshold here, you dramatically reduce False Positives compared to a simple hardcoded limit.
2. **Treating Features Independently:** You calculate Z-scores per feature instead of combining them into a massive single score. This makes the system "explainable" (you know *exactly* which metric failed), which is crucial for the ML layer Hamza is building.
