import threading, time
from fastapi import Request, Response

class TokenBucketLimiter:
    def __init__(self, rate=0, burst=10):
        self.rate = float(rate or 0)
        self.burst = int(burst or 10)
        self.buckets = {}
        self.lock = threading.Lock()

    def allow(self, key):
        if self.rate <= 0:
            return True, 0
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self.buckets[key] = (tokens - 1, now)
                return True, 0
            retry = max(1, int((1 - tokens) / self.rate + 0.999))
            self.buckets[key] = (tokens, now)
            return False, retry

async def rate_limit_middleware(request: Request, call_next):
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter:
        ip = request.client.host if request.client else "unknown"
        ok, retry = limiter.allow(ip)
        if not ok:
            return Response("Too Many Requests", status_code=429, headers={"Retry-After": str(retry)})
    return await call_next(request)
