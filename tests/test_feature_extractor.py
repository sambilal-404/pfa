"""
Tests for request feature extraction.
"""

from __future__ import annotations

import pytest

from src.engine.feature_extractor import FeatureExtractor, RequestFeatures


class TestFeatureExtractor:
    """Tests for the FeatureExtractor class."""
    
    def test_url_length_extraction(self, feature_extractor: FeatureExtractor):
        """Should correctly extract URL length."""
        features = feature_extractor.extract(url="/api/users")
        assert features.url_length == 10
    
    def test_body_length_extraction(self, feature_extractor: FeatureExtractor):
        """Should correctly extract body length."""
        features = feature_extractor.extract(
            url="/api/test",
            body='{"name": "test"}',
        )
        assert features.body_length == 16
    
    def test_query_param_count(self, feature_extractor: FeatureExtractor):
        """Should correctly count query parameters."""
        features = feature_extractor.extract(
            url="/api/users?page=1&limit=10&sort=name",
        )
        assert features.query_param_count == 3
    
    def test_no_query_params(self, feature_extractor: FeatureExtractor):
        """Should return 0 for URLs without query params."""
        features = feature_extractor.extract(url="/api/users/")
        assert features.query_param_count == 0
    
    def test_special_char_count(self, feature_extractor: FeatureExtractor):
        """Should correctly count special characters."""
        features = feature_extractor.extract(
            url="/api/test?filter=a>b&val=c<d",
        )
        # > and < are special chars
        assert features.special_char_count >= 2
    
    def test_entropy_normal_text(self, feature_extractor: FeatureExtractor):
        """Should calculate reasonable entropy for normal text."""
        features = feature_extractor.extract(
            url="/api/users",
            body="Hello World",
        )
        # Normal English text has entropy around 3-4 bits
        assert 2.0 < features.entropy < 5.0
    
    def test_entropy_high_random(self, feature_extractor: FeatureExtractor):
        """Should detect high entropy in random strings."""
        random_string = "a8Kj3mP9xL2nQ5wR7vT1yB4cF6gH0jD"
        features = feature_extractor.extract(
            url="/api/test",
            body=random_string,
        )
        # Random strings have higher entropy
        assert features.entropy > 3.5
    
    def test_entropy_empty_string(self, feature_extractor: FeatureExtractor):
        """Should return 0 entropy for empty string."""
        features = feature_extractor.extract(url="", body="")
        assert features.entropy == 0.0
    
    def test_header_count(self, feature_extractor: FeatureExtractor):
        """Should correctly count headers."""
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": "Bearer token",
        }
        features = feature_extractor.extract(
            url="/api/test",
            headers=headers,
        )
        assert features.header_count == 3
    
    def test_numeric_ratio(self, feature_extractor: FeatureExtractor):
        """Should calculate numeric character ratio."""
        features = feature_extractor.extract(
            url="/api/12345",
            body="abc123def",
        )
        # 5 digits in URL + 3 digits in body = 8 / (8+9) ≈ 0.47
        assert 0.3 < features.numeric_char_ratio < 0.6
    
    def test_empty_inputs(self, feature_extractor: FeatureExtractor):
        """Should handle all empty inputs gracefully."""
        features = feature_extractor.extract(
            url="",
            body=None,
            headers=None,
        )
        
        assert features.url_length == 0
        assert features.body_length == 0
        assert features.query_param_count == 0
        assert features.special_char_count == 0
        assert features.entropy == 0.0
        assert features.header_count == 0
        assert features.numeric_char_ratio == 0.0
    
    def test_to_dict(self, feature_extractor: FeatureExtractor):
        """Should serialize to dictionary correctly."""
        features = feature_extractor.extract(url="/api/test")
        features_dict = features.to_dict()
        
        assert isinstance(features_dict, dict)
        assert "url_length" in features_dict
        assert "entropy" in features_dict
        # All values should be floats
        for v in features_dict.values():
            assert isinstance(v, float)
    
    def test_shannon_entropy_direct(self):
        """Direct test for Shannon entropy calculation."""
        # Uniform distribution over 8 characters
        uniform = "abcdefgh"
        entropy = FeatureExtractor.calculate_shannon_entropy(uniform)
        assert abs(entropy - 3.0) < 0.01  # log2(8) = 3.0
        
        # All same character
        same = "aaaaaaa"
        entropy = FeatureExtractor.calculate_shannon_entropy(same)
        assert entropy == 0.0
