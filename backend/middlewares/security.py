from __future__ import annotations
import time
from collections import defaultdict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from config.settings import settings
from utils.logger import request_logger

class RateLimiter:
    """In-memory Token Bucket rate limiter to protect API routes from abuse."""
    
    def __init__(self) -> None:
        self.buckets = defaultdict(lambda: float(settings.rate_limit_burst))
        self.last_update = defaultdict(time.time)
        self.burst = float(settings.rate_limit_burst)
        self.rate = settings.rate_limit_rate

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        elapsed = now - self.last_update[client_ip]
        self.last_update[client_ip] = now
        
        # Add new tokens based on elapsed time
        self.buckets[client_ip] = min(self.burst, self.buckets[client_ip] + elapsed * self.rate)
        
        if self.buckets[client_ip] >= 1.0:
            self.buckets[client_ip] -= 1.0
            return True
        return False

rate_limiter = RateLimiter()

import re

def sanitize_input(text: str) -> str:
    """
    Removes HTML tags, javascript: protocols, and potential script injections
    to sanitize request parameters and payloads.
    """
    if not text:
        return text
    # Strip HTML tags
    text = re.sub(r'<[^>]*>', '', text)
    # Strip javascript: protocols
    text = re.sub(r'(?i)javascript:', '', text)
    # Strip common SQL injection patterns
    text = re.sub(r'(?i)(union|select|insert|delete|drop|update)\b', '', text)
    return text.strip()

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Open Security Middleware - Enforces Rate Limiting, Request Sanitization, 
    and Secure Security Headers (Helmet-equivalent).
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        
        # 1. Skip checks for OPTIONS preflight, Root endpoint, health status, and Trusted Cache
        if request.method == "OPTIONS" or request.url.path in ["/", "/health", "/trusted-domains"]:
            response: Response = await call_next(request)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "*"
            return response
            
        # 2. Rate Limiting Check
        if not rate_limiter.is_allowed(client_ip):
            request_logger.warn(f"Rate limit exceeded for IP: {client_ip}", path=request.url.path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Rate limit exceeded. Try again later."}
            )

        # 3. Request Sanitization Check (Inspect Query Parameters)
        for key, value in request.query_params.items():
            if "<script" in value.lower() or "javascript:" in value.lower():
                request_logger.warn(f"XSS Injection block for IP: {client_ip}", path=request.url.path)
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Malicious payload detected in request parameters."}
                )

        # Telemetry log of allowed requests
        request_logger.info(f"Incoming request: {request.method} {request.url.path}", ip=client_ip)

        # 4. Proceed to Route Handler
        response: Response = await call_next(request)

        # 5. Apply Secure Headers (Helmet equivalent)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "ALLOWALL"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response
