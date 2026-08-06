import sys
import os

# Allow running directly from backend/ or from repository root
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import asyncio
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from dotenv import load_dotenv

load_dotenv()

from config.settings import settings
from middlewares.security import SecurityMiddleware
from middlewares.error_handler import (
    ErrorHandlingMiddleware,
    validation_exception_handler,
    http_exception_handler
)
from controllers import analyze, dashboard
from services.threat_intel import intel_db
from utils.logger import app_logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Triggers background intelligence updates upon API startup."""
    app_logger.info("Starting Zerion Intelligence Engine backend services...")
    asyncio.create_task(intel_db.update_feeds())
    yield

# Initialize FastAPI App
app = FastAPI(
    title="Zerion Intelligence Engine",
    description="Zerion Intelligence Engine API - AI-Powered Browser Security Platform",
    version="2.0.0",
    lifespan=lifespan
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
    import os
    import sys
    
    # Disable reload by default on Windows to prevent orphaned background processes
    # from locking port 7860.
    is_windows = sys.platform.startswith("win")
    default_reload = "false" if is_windows else "true"
    reload_env = os.getenv("ZERION_RELOAD", default_reload).lower() == "true"
    
    uvicorn.run("app:app", host="0.0.0.0", port=7860, reload=reload_env)
