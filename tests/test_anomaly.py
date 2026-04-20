"""
Tests for statistical anomaly detection.
"""

from __future__ import annotations

import pytest

from src.config import AnomalyConfig
from src.engine.anomaly_detector import AnomalyDetector
from src.engine.feature_extractor import RequestFeatures


class TestAnomalyDetector:
    """Tests for the AnomalyDetector class."""
    
    def test_normal_features_no_anomaly(self, anomaly_detector: AnomalyDetector):
        """Should not flag normal features as anomalous."""
        features = RequestFeatures(
            url_length=50,
            body_length=100,
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        assert report.is_anomalous is False
        assert report.anomaly_count == 0
    
    def test_high_url_length_anomaly(self, anomaly_detector: AnomalyDetector):
        """Should detect anomalously long URLs."""
        # With baseline mean=45, std=25, 3-sigma threshold is 120
        features = RequestFeatures(
            url_length=500,  # Very anomalous
            body_length=100,
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        assert report.is_anomalous is True
        assert report.anomaly_count >= 1
        
        url_score = report.scores["url_length"]
        assert url_score.is_anomaly is True
        assert url_score.z_score > 3.0
    
    def test_high_entropy_anomaly(self, anomaly_detector: AnomalyDetector):
        """Should detect high entropy payloads."""
        # With baseline mean=3.2, std=0.8, 3-sigma threshold is 5.6
        features = RequestFeatures(
            url_length=50,
            body_length=100,
            query_param_count=2,
            special_char_count=50,
            entropy=7.5,  # Very high entropy
            header_count=5,
            numeric_char_ratio=0.3,
        )
        
        report = anomaly_detector.analyze(features)
        assert report.is_anomalous is True
        
        entropy_score = report.scores["entropy"]
        assert entropy_score.is_anomaly is True
    
    def test_multiple_anomalies(self, anomaly_detector: AnomalyDetector):
        """Should count multiple anomalous features."""
        features = RequestFeatures(
            url_length=500,  # Anomalous
            body_length=1000,  # Anomalous
            query_param_count=50,  # Anomalous
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        assert report.anomaly_count >= 3
    
    def test_disabled_detection(self):
        """Should return empty report when disabled."""
        config = AnomalyConfig(enable_detection=False)
        detector = AnomalyDetector(config)
        
        features = RequestFeatures(
            url_length=9999,
            body_length=9999,
            query_param_count=999,
            special_char_count=999,
            entropy=9.9,
            header_count=100,
            numeric_char_ratio=0.9,
        )
        
        report = detector.analyze(features)
        assert report.is_anomalous is False
        assert report.anomaly_count == 0
        assert len(report.scores) == 0
    
    def test_custom_threshold(self):
        """Should use custom sigma threshold."""
        config = AnomalyConfig(sigma_threshold=2.0)
        detector = AnomalyDetector(config)
        
        # This would be normal at 3-sigma but anomalous at 2-sigma
        features = RequestFeatures(
            url_length=100,  # mean=45, std=25, z-score=2.2
            body_length=100,
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = detector.analyze(features)
        assert report.is_anomalous is True
    
    def test_z_score_calculation(self, anomaly_detector: AnomalyDetector):
        """Should calculate z-scores correctly."""
        features = RequestFeatures(
            url_length=120,  # mean=45, std=25, z=(120-45)/25=3.0
            body_length=100,
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        url_score = report.scores["url_length"]
        
        # z_score should be approximately 3.0
        assert abs(url_score.z_score - 3.0) < 0.01
    
    def test_max_z_score_tracking(self, anomaly_detector: AnomalyDetector):
        """Should track the maximum z-score across features."""
        features = RequestFeatures(
            url_length=200,  # z = (200-45)/25 = 6.2
            body_length=500,  # z = (500-120)/100 = 3.8
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        assert report.max_z_score >= 6.0
    
    def test_baseline_update(self, anomaly_detector: AnomalyDetector):
        """Should allow baseline updates."""
        anomaly_detector.update_baseline("url_length", mean=100, std=50)
        
        baselines = anomaly_detector.baselines
        assert baselines["url_length"]["mean"] == 100
        assert baselines["url_length"]["std"] == 50
    
    def test_report_serialization(self, anomaly_detector: AnomalyDetector):
        """Should serialize report to dict correctly."""
        features = RequestFeatures(
            url_length=50,
            body_length=100,
            query_param_count=2,
            special_char_count=8,
            entropy=3.2,
            header_count=5,
            numeric_char_ratio=0.1,
        )
        
        report = anomaly_detector.analyze(features)
        report_dict = report.to_dict()
        
        assert isinstance(report_dict, dict)
        assert "scores" in report_dict
        assert "anomaly_count" in report_dict
        assert "is_anomalous" in report_dict
        assert "max_z_score" in report_dict
