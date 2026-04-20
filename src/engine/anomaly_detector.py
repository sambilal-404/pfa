"""
Anomaly Detector - Statistical outlier detection.

Implements 3-sigma rule for detecting requests that deviate
significantly from established baselines.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from src.config import AnomalyConfig
from src.engine.feature_extractor import RequestFeatures


@dataclass(frozen=True)
class AnomalyScore:
    """
    Anomaly score for a single feature.
    
    Attributes:
        feature_name: Name of the feature
        value: Actual observed value
        mean: Baseline mean
        std: Baseline standard deviation
        z_score: Number of standard deviations from mean
        is_anomaly: Whether this feature is anomalous
        threshold: Sigma threshold used
    """
    feature_name: str
    value: float
    mean: float
    std: float
    z_score: float
    is_anomaly: bool
    threshold: float
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "feature_name": self.feature_name,
            "value": self.value,
            "mean": self.mean,
            "std": self.std,
            "z_score": round(self.z_score, 4),
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
        }


@dataclass(frozen=True)
class AnomalyReport:
    """
    Complete anomaly analysis report.
    
    Attributes:
        scores: Per-feature anomaly scores
        anomaly_count: Number of anomalous features
        is_anomalous: Whether any features are anomalous
        max_z_score: Highest z-score across all features
    """
    scores: Dict[str, AnomalyScore]
    anomaly_count: int
    is_anomalous: bool
    max_z_score: float
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "scores": {k: v.to_dict() for k, v in self.scores.items()},
            "anomaly_count": self.anomaly_count,
            "is_anomalous": self.is_anomalous,
            "max_z_score": round(self.max_z_score, 4),
        }


class AnomalyDetector:
    """
    Statistical anomaly detector using the 3-sigma rule.
    
    The 3-sigma rule states that for a normal distribution,
    99.7% of data falls within 3 standard deviations of the mean.
    Values outside this range are considered anomalies.
    
    Design Notes:
    - Uses configurable baselines (can be updated from real traffic)
    - Supports incremental baseline updates
    - Handles zero std deviation gracefully
    - All features are treated independently
    
    Args:
        config: Anomaly detection configuration
    """
    
    # Features to analyze for anomalies
    ANALYSIS_FEATURES = [
        "url_length",
        "body_length", 
        "query_param_count",
        "special_char_count",
        "entropy",
    ]
    
    def __init__(self, config: Optional[AnomalyConfig] = None) -> None:
        self._config = config or AnomalyConfig()
        # Deep copy baselines to avoid mutation
        self._baselines: Dict[str, Dict[str, float]] = {
            k: v.copy() for k, v in self._config.baselines.items()
        }
    
    @property
    def baselines(self) -> Dict[str, Dict[str, float]]:
        """Return a copy of current baselines."""
        return {k: v.copy() for k, v in self._baselines.items()}
    
    def update_baseline(
        self,
        feature_name: str,
        mean: float,
        std: float
    ) -> None:
        """
        Update baseline statistics for a feature.
        
        Args:
            feature_name: Name of the feature
            mean: New mean value
            std: New standard deviation
        """
        if feature_name in self._baselines:
            self._baselines[feature_name]["mean"] = mean
            self._baselines[feature_name]["std"] = max(std, 0.01)  # Prevent zero std
    
    def _calculate_z_score(
        self,
        value: float,
        mean: float,
        std: float
    ) -> float:
        """
        Calculate z-score (number of standard deviations from mean).
        
        Args:
            value: Observed value
            mean: Baseline mean
            std: Baseline standard deviation
            
        Returns:
            Z-score (can be negative for values below mean)
        """
        if std <= 0:
            # If std is zero or negative, any deviation is anomalous
            return float('inf') if value != mean else 0.0
        return (value - mean) / std
    
    def analyze(self, features: RequestFeatures) -> AnomalyReport:
        """
        Analyze features for statistical anomalies.
        
        Args:
            features: Extracted request features
            
        Returns:
            Complete anomaly report with per-feature scores
        """
        if not self._config.enable_detection:
            return AnomalyReport(
                scores={},
                anomaly_count=0,
                is_anomalous=False,
                max_z_score=0.0,
            )
        
        features_dict = features.to_dict()
        scores: Dict[str, AnomalyScore] = {}
        anomaly_count = 0
        max_z_score = 0.0
        
        for feature_name in self.ANALYSIS_FEATURES:
            if feature_name not in features_dict:
                continue
            
            value = features_dict[feature_name]
            baseline = self._baselines.get(feature_name, {"mean": 0.0, "std": 1.0})
            mean = baseline["mean"]
            std = baseline["std"]
            
            z_score = self._calculate_z_score(value, mean, std)
            is_anomaly = abs(z_score) > self._config.sigma_threshold
            
            if is_anomaly:
                anomaly_count += 1
            if abs(z_score) > max_z_score:
                max_z_score = abs(z_score)
            
            scores[feature_name] = AnomalyScore(
                feature_name=feature_name,
                value=value,
                mean=mean,
                std=std,
                z_score=z_score,
                is_anomaly=is_anomaly,
                threshold=self._config.sigma_threshold,
            )
        
        return AnomalyReport(
            scores=scores,
            anomaly_count=anomaly_count,
            is_anomalous=anomaly_count > 0,
            max_z_score=max_z_score,
        )
