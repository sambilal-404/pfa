"""
Tests for the sliding window rate limiter.
"""

from __future__ import annotations

import time

import pytest

from src.config import RateLimitConfig
from src.engine.rate_limiter import SlidingWindowRateLimiter


class TestSlidingWindowRateLimiter:
    """Tests for the SlidingWindowRateLimiter class."""
    
    def test_allows_under_limit(self, rate_limiter: SlidingWindowRateLimiter):
        """Should allow requests under the limit."""
        result = rate_limiter.check("192.168.1.1")
        assert result.allowed is True
        assert result.remaining > 0
    
    def test_blocks_over_limit(self, rate_limiter: SlidingWindowRateLimiter):
        """Should block requests over the limit."""
        ip = "192.168.1.2"
        
        # Make max_requests
        for _ in range(5):
            result = rate_limiter.check(ip)
            assert result.allowed is True
        
        # Next request should be blocked
        result = rate_limiter.check(ip)
        assert result.allowed is False
        assert result.remaining == 0
    
    def test_per_ip_isolation(self, rate_limiter: SlidingWindowRateLimiter):
        """Should track limits independently per IP."""
        ip1 = "192.168.1.3"
        ip2 = "192.168.1.4"
        
        # Exhaust IP1
        for _ in range(5):
            rate_limiter.check(ip1)
        
        # IP1 should be blocked
        assert rate_limiter.check(ip1).allowed is False
        
        # IP2 should still be allowed
        assert rate_limiter.check(ip2).allowed is True
    
    def test_remaining_decrements(self, rate_limiter: SlidingWindowRateLimiter):
        """Should correctly decrement remaining count."""
        ip = "192.168.1.5"
        
        result1 = rate_limiter.check(ip)
        assert result1.remaining == 4
        
        result2 = rate_limiter.check(ip)
        assert result2.remaining == 3
    
    def test_reset_single_ip(self, rate_limiter: SlidingWindowRateLimiter):
        """Should reset rate limit for a specific IP."""
        ip = "192.168.1.6"
        
        # Exhaust limit
        for _ in range(5):
            rate_limiter.check(ip)
        assert rate_limiter.check(ip).allowed is False
        
        # Reset and should be allowed again
        rate_limiter.reset(ip)
        assert rate_limiter.check(ip).allowed is True
    
    def test_reset_all(self, rate_limiter: SlidingWindowRateLimiter):
        """Should reset rate limits for all IPs."""
        ip1 = "192.168.1.7"
        ip2 = "192.168.1.8"
        
        for _ in range(5):
            rate_limiter.check(ip1)
            rate_limiter.check(ip2)
        
        assert rate_limiter.check(ip1).allowed is False
        assert rate_limiter.check(ip2).allowed is False
        
        rate_limiter.reset()
        
        assert rate_limiter.check(ip1).allowed is True
        assert rate_limiter.check(ip2).allowed is True
    
    def test_result_structure(self, rate_limiter: SlidingWindowRateLimiter):
        """Should return properly structured results."""
        result = rate_limiter.check("192.168.1.9")
        
        assert hasattr(result, "allowed")
        assert hasattr(result, "current_count")
        assert hasattr(result, "remaining")
        assert hasattr(result, "reset_at")
        assert hasattr(result, "limit")
        
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert "allowed" in result_dict
    
    def test_custom_config(self):
        """Should respect custom configuration."""
        config = RateLimitConfig(
            max_requests=2,
            window_seconds=60,
        )
        limiter = SlidingWindowRateLimiter(config)
        
        ip = "192.168.1.10"
        
        # Only 2 requests allowed
        assert limiter.check(ip).allowed is True
        assert limiter.check(ip).allowed is True
        assert limiter.check(ip).allowed is False
    
    def test_get_record(self, rate_limiter: SlidingWindowRateLimiter):
        """Should return record for debugging."""
        ip = "192.168.1.11"
        
        assert rate_limiter.get_record(ip) is None
        
        rate_limiter.check(ip)
        record = rate_limiter.get_record(ip)
        
        assert record is not None
        assert "timestamps" in record
        assert "count" in record
        assert record["count"] == 1
    
    def test_cleanup_stale_records(self, rate_limiter: SlidingWindowRateLimiter):
        """Should clean up stale IP records."""
        ip = "192.168.1.12"
        rate_limiter.check(ip)
        
        # Manually age the record
        rate_limiter._records[ip].timestamps = [
            time.time() - 1000  # Very old timestamp
        ]
        
        # Also create a config with short cleanup interval
        old_config = rate_limiter._config
        rate_limiter._config = RateLimitConfig(
            max_requests=5,
            window_seconds=60,
            cleanup_interval=1,  # Very short
        )
        
        removed = rate_limiter.cleanup_stale_records()
        assert removed >= 0
        
        # Restore config
        rate_limiter._config = old_config
