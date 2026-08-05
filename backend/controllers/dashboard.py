import time
import requests
import zipfile
import io
from fastapi import APIRouter
from backend.database.db import get_db_stats, get_recent_scans_logs
from backend.utils.logger import error_logger, app_logger

router = APIRouter()

# In-memory Tranco trusted domains list cache
trusted_cache = {
    "timestamp": 0.0,
    "domains": []
}

@router.get("/dashboard/stats")
async def get_stats() -> dict:
    """Returns aggregated aggregates, timelines, and severities from threat database logs."""
    return get_db_stats()

@router.get("/dashboard/recent")
async def get_recent_scans() -> list[dict]:
    """Returns the 20 most recent threat evaluations recorded in database."""
    return get_recent_scans_logs(limit=20)

@router.get("/trusted-domains")
def get_trusted_domains() -> dict:
    """
    Downloads and caches the Tranco Top 10k list to avoid zero-day overhead 
    on highly reputable sites.
    """
    global trusted_cache
    current_time = time.time()
    
    # 24-hour cache refresh check (86400 seconds)
    if current_time - trusted_cache["timestamp"] > 86400 or not trusted_cache["domains"]:
        try:
            app_logger.info("WADE: Downloading latest Tranco Top 10k list...")
            url = "https://tranco-list.eu/top-1m.csv.zip"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    csv_name = z.namelist()[0]
                    with z.open(csv_name) as f:
                        domains = []
                        for i, line in enumerate(f):
                            if i >= 10000: 
                                break
                            domain = line.decode('utf-8').strip().split(',')[1]
                            domains.append(domain)
                            
                custom_safe = ["paruluniversity.ac.in"]
                trusted_cache["domains"] = list(set(domains + custom_safe))
                trusted_cache["timestamp"] = current_time
                app_logger.info(f"WADE: Successfully cached {len(trusted_cache['domains'])} trusted domains.")
            
        except Exception as e:
            error_logger.error("Failed to sync Tranco list. Reverting to backup domains.", e)
            if not trusted_cache["domains"]:
                trusted_cache["domains"] = [
                    "google.com", "youtube.com", "github.com", 
                    "wikipedia.org", "microsoft.com", "paruluniversity.ac.in"
                ]

    return {"success": True, "domains": trusted_cache["domains"]}
