"""
Feature Extractor - Transforms raw requests into numerical features.

Extracts security-relevant features from API requests for
anomaly detection and analysis.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class RequestFeatures:
    """
    Extracted numerical features from a request.
    
    All features are designed to be useful for both statistical
    anomaly detection and ML-based classification.
    """
    url_length: int
    body_length: int
    query_param_count: int
    special_char_count: int
    entropy: float
    header_count: int
    numeric_char_ratio: float
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for serialization."""
        return {
            "url_length": float(self.url_length),
            "body_length": float(self.body_length),
            "query_param_count": float(self.query_param_count),
            "special_char_count": float(self.special_char_count),
            "entropy": self.entropy,
            "header_count": float(self.header_count),
            "numeric_char_ratio": self.numeric_char_ratio,
        }


# Characters considered "special" for security analysis
SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;:',.<>?/~`\\\"")


class FeatureExtractor:
    """
    Extracts security-relevant features from API requests.
    
    Design Notes:
    - Pure functions for testability
    - Handles edge cases gracefully (empty strings, None values)
    - Features chosen based on WAF industry research
    """
    
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Shannon entropy measures the uncertainty/randomness in a string.
        High entropy (>4.0) often indicates encoded or encrypted payloads.
        Low entropy (<2.0) suggests simple, repetitive content.
        
        Args:
            data: Input string
            
        Returns:
            Entropy value in bits (0.0 to ~8.0 for ASCII)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    @staticmethod
    def count_special_characters(data: str) -> int:
        """Count special characters in a string."""
        if not data:
            return 0
        return sum(1 for c in data if c in SPECIAL_CHARS)
    
    @staticmethod
    def count_query_params(url: str) -> int:
        """Count the number of query parameters in a URL."""
        if not url:
            return 0
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return 0
            params = parse_qs(parsed.query)
            return len(params)
        except Exception:
            return 0
    
    @staticmethod
    def calculate_numeric_ratio(data: str) -> float:
        """Calculate the ratio of numeric characters to total characters."""
        if not data:
            return 0.0
        numeric_count = sum(1 for c in data if c.isdigit())
        return round(numeric_count / len(data), 4) if data else 0.0
    
    @classmethod
    def extract(
        cls,
        url: str,
        body: Optional[str] = None,
        headers: Optional[dict] = None
    ) -> RequestFeatures:
        """
        Extract all features from a request.
        
        Args:
            url: Request URL path (including query string)
            body: Request body as string (can be None)
            headers: Request headers as dict (can be None)
            
        Returns:
            RequestFeatures dataclass with all extracted values
        """
        body = body or ""
        headers = headers or {}
        
        # Combine relevant data for entropy calculation
        combined_data = f"{url}{body}"
        
        return RequestFeatures(
            url_length=len(url),
            body_length=len(body),
            query_param_count=cls.count_query_params(url),
            special_char_count=cls.count_special_characters(combined_data),
            entropy=cls.calculate_shannon_entropy(combined_data),
            header_count=len(headers),
            numeric_char_ratio=cls.calculate_numeric_ratio(combined_data),
        )
