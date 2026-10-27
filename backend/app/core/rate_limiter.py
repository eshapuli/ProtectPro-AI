import time
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory Rate Limiting Middleware.
    Protects sensitive endpoints (e.g. auth and analysis) from brute force and DoS.
    Enforces a strict sliding window per IP address without paid third-party dependencies.
    """
    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # client_ip -> list of timestamps
        self.clients: Dict[str, list] = {}

    async def dispatch(self, request: Request, call_next):
        # Allow open health check
        if request.url.path == "/":
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        if client_ip not in self.clients:
            self.clients[client_ip] = []

        # Prune old timestamps
        cutoff = now - self.window_seconds
        self.clients[client_ip] = [t for t in self.clients[client_ip] if t > cutoff]

        # Rate limit checks: More stringent for auth endpoints
        limit = 15 if "/auth/" in request.url.path else self.max_requests
        if len(self.clients[client_ip]) >= limit:
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: maximum {limit} requests per minute permitted."},
                headers={"Retry-After": "60"}
            )

        self.clients[client_ip].append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - len(self.clients[client_ip])))
        return response
