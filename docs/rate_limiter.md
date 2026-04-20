# Rate Limiter (`rate_limiter.py`)

## Purpose of the file
This file implements the **Rate Limiting** layer (Layer 2). Its goal is to prevent volumetric attacks like Brute Force, DDoS, or Credential Stuffing by restricting the number of requests a single IP address can make within a specific time window.

## Step-by-Step Explanation
1. **Tracking by IP:** The `SlidingWindowRateLimiter` maintains a dictionary called `_records`. The key is the user's IP address, and the value is an `_IPRecord` object containing a list of `timestamps`.
2. **Incoming Request:** When an IP hits the API, the `check(ip_address)` method is called.
3. **Defining the Window:** It calculates `window_start` (current time minus `window_seconds`, e.g., Now - 60s).
4. **Lazy Cleanup:** Instead of having a background process constantly cleaning memory, it cleans up *on the fly*. It iterates through the IP's timestamps and keeps *only* the ones strictly greater than `window_start`.
5. **Counting:** It counts the remaining timestamps. If the count is >= `max_requests`, the request is blocked. Otherwise, the new timestamp is appended, and the request is allowed.

## Important Functions & Classes
- `_IPRecord`: A dataclass storing a simple list of floats (timestamps) for an IP.
- `SlidingWindowRateLimiter.check()`: Executes the core logic. Notice the line:
  `record.timestamps = [ts for ts in record.timestamps if ts > window_start]`
  This is the exact line where old requests expire and "slide" out of the window.

## Real Examples from My Code
Imagine a limit of 100 requests per 60 seconds.
- `now = time.time()` (let's say 12:01:00)
- `window_start = now - 60` (12:00:00)
- The list comprehension filters out any request made at 11:59:59.
- If the remaining list length is 100, the new request at 12:01:00 is rejected, and `reset_at` is calculated based on the oldest request still in the list.

## Key Decisions & Why They Matter
1. **Sliding Window vs Fixed Window:** You chose Sliding Window because Fixed Window is vulnerable to "bursts" at the edge of the minute boundary. Your implementation perfectly prevents this.
2. **Lazy Cleanup Memory Leak Risk:** Because you only clean up timestamps *when an IP makes a new request*, an IP that makes 1 request and never returns will stay in the `_records` dictionary forever. This is a known limitation of in-memory dictionaries that you should mention in your defense! (A production fix would be using Redis with TTL).
