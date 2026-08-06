from __future__ import annotations
import os
import secrets
from typing import Optional
from pydantic import BaseModel

class Settings(BaseModel):
    """Application configuration and credentials loader."""
    
    # API Keys & Credentials
    gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
    groq_api_key: Optional[str] = os.getenv("GROQ_API_KEY")
    virustotal_api_key: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    
    # Unified Threat Intelligence API keys (Phase 3)
    urlscan_api_key: Optional[str] = os.getenv("URLSCAN_API_KEY")
    google_safe_browsing_key: Optional[str] = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    abuseipdb_key: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
    
    # Authentication Secrets — MUST be set via environment variables in production
    # WARNING: Fallback values below are development-only; never deploy without overrides
    zerion_api_key: str = os.getenv("ZERION_API_KEY", "zerion_secret_key_v2")
    jwt_secret: str = os.getenv("JWT_SECRET", "super_secret_jwt_key_zerion_v2")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    
    # Database Settings
    db_path: str = os.getenv("DB_PATH", "zerion_logs.db")
    
    # Rate Limiting Parameters (Token Bucket Algorithm)
    rate_limit_burst: int = int(os.getenv("RATE_LIMIT_BURST", "30"))
    rate_limit_rate: float = float(os.getenv("RATE_LIMIT_RATE", "1.0"))  # Refill rate per second

settings = Settings()
