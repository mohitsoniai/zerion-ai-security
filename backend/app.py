import asyncio
import sqlite3
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv

load_dotenv()

from backend.config.settings import settings
from backend.middlewares.security import SecurityMiddleware
from backend.middlewares.error_handler import (
    ErrorHandlingMiddleware,
    validation_exception_handler,
    http_exception_handler
)
from backend.controllers import analyze, dashboard
from backend.services.threat_intel import intel_db
from backend.utils.logger import app_logger

# Initialize FastAPI App
app = FastAPI(
    title="WADE Engine Ultimate",
    description="Web AI Defense Engine API - AI-Powered Web Security Platform",
    version="2.0.0"
)

# 1. CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Open Security Middlewares (Rate limiting, helmet headers, no auth)
app.add_middleware(SecurityMiddleware)

# 3. Exception Middlewares
app.add_middleware(ErrorHandlingMiddleware)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)

# 4. Routing Controller Routers
app.include_router(analyze.router)
app.include_router(dashboard.router)

@app.on_event("startup")
async def startup_event() -> None:
    """Triggers background intelligence updates upon API startup."""
    app_logger.info("Starting WADE Engine backend services...")
    asyncio.create_task(intel_db.update_feeds())

@app.get("/health")
async def health_check() -> JSONResponse:
    """
    Service Health Status endpoint returning status metrics, cache states, 
    and threat feeds count.
    """
    db_ok = True
    cache_records = 0
    api_cache_records = 0
    try:
        with sqlite3.connect(settings.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM threat_intel_cache")
            cache_records = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM api_cache")
            api_cache_records = cursor.fetchone()[0]
    except Exception as e:
        db_ok = False
        app_logger.error("Health check: SQLite database check failed", e)
        
    return JSONResponse(
        status_code=200 if db_ok else 500,
        content={
            "status": "healthy" if db_ok else "degraded",
            "database": "connected" if db_ok else "disconnected",
            "threat_feeds_loaded": intel_db.loaded,
            "threat_feeds_entries": len(intel_db.malicious_urls),
            "threat_intel_cache_size": cache_records,
            "api_cache_size": api_cache_records
        }
    )


@app.get("/", response_class=HTMLResponse)
async def read_root() -> str:
    """Root entry point landing page - Web-based Command Center Dashboard."""
    import os
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="0.0.0.0", port=7860, reload=True)
