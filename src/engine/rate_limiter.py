"""
Sliding Window Rate Limiter.

Implements in-memory rate limiting using the sliding window algorithm.
Designed for high-throughput API protection.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from src.config import RateLimitConfig


@dataclass(frozen=True)
class RateLimitResult:
    """
    Result of a rate limit check.
    
    Attributes:
        allowed: Whether the request is allowed
        current_count: Number of requests in the current window
        remaining: Number of requests remaining before limit
        reset_at: Timestamp when the window resets
        limit: Maximum requests allowed in the window
    """
    allowed: bool
    current_count: int
    remaining: int
    reset_at: float
    limit: int
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "allowed": self.allowed,
            "current_count": self.current_count,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "limit": self.limit,
        }


@dataclass
class _IPRecord:
    """Internal tracking record for a single IP address."""
    timestamps: Deque[float] = field(default_factory=deque)
    last_cleanup: float = field(default_factory=time.monotonic)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter with per-IP tracking.
    
    Algorithm:
    - For each request, filter timestamps within the window
    - If count >= max_requests, deny the request
    - Otherwise, add current timestamp and allow
    
    Design Notes:
    - Uses lazy cleanup (removes stale entries on access)
    - O(n) per check where n is requests in window (typically small)
    - Memory-efficient: only stores timestamps
    - For distributed systems, consider Redis-based implementation
    
    Args:
        config: Rate limit configuration
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None) -> None:
        self._config = config or RateLimitConfig()
        self._records: Dict[str, _IPRecord] = {}
    
    def check(self, ip_address: str) -> RateLimitResult:
        """
        Check if a request from the given IP should be allowed.
        
        Args:
            ip_address: Client IP address
            
        Returns:
            RateLimitResult with detailed status
        """
        now = time.monotonic()
        window_start = now - self._config.window_seconds
        
        # Get or create record
        record = self._records.get(ip_address)
        if record is None:
            record = _IPRecord()
            self._records[ip_address] = record
        
        # Expire stale timestamps from the left of the deque
        while record.timestamps and record.timestamps[0] <= window_start:
            record.timestamps.popleft()
        
        current_count = len(record.timestamps)
        remaining = max(0, self._config.max_requests - current_count)
        
        if current_count >= self._config.max_requests:
            oldest = record.timestamps[0]
            reset_at = oldest + self._config.window_seconds
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                remaining=0,
                reset_at=reset_at,
                limit=self._config.max_requests,
            )
        
        # Record current request timestamp
        record.timestamps.append(now)
        new_count = current_count + 1
        new_remaining = max(0, self._config.max_requests - new_count)
        
        return RateLimitResult(
            allowed=True,
            current_count=new_count,
            remaining=new_remaining,
            reset_at=now + self._config.window_seconds,
            limit=self._config.max_requests,
        )
    
    def cleanup_stale_records(self) -> int:
        """
        Remove IP records that have no recent activity.
        
        Returns:
            Number of records removed
        """
        now = time.time()
        threshold = now - (self._config.cleanup_interval * 2)
        
        stale_ips = [
            ip for ip, record in self._records.items()
            if not record.timestamps or record.timestamps[-1] < threshold
        ]
        
        for ip in stale_ips:
            del self._records[ip]
        
        return len(stale_ips)
    
    def reset(self, ip_address: Optional[str] = None) -> None:
        """
        Reset rate limit for a specific IP or all IPs.
        
        Args:
            ip_address: Specific IP to reset, or None for all
        """
        if ip_address is None:
            self._records.clear()
        elif ip_address in self._records:
            del self._records[ip_address]
    
    def get_record(self, ip_address: str) -> Optional[dict]:
        """Get current rate limit record for an IP (for debugging)."""
        record = self._records.get(ip_address)
        if record is None:
            return None
        return {
            "timestamps": record.timestamps.copy(),
            "count": len(record.timestamps),
        }
