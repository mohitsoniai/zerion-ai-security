from __future__ import annotations
import asyncio
import socket
import base64
import httpx
from typing import Optional
from config.settings import settings
from database.db import get_threat_intel_cache, set_threat_intel_cache
from utils.logger import error_logger, app_logger
from services.threat_intel import intel_db

async def query_google_safe_browsing(url: str) -> dict:
    """Queries the Google Safe Browsing API v4 for threat classification."""
    if not settings.google_safe_browsing_key:
        return {"matches": False, "threats": []}
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_key}"
        payload = {
            "client": {"clientId": "zerion-ai-v2", "clientVersion": "5.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with httpx.AsyncClient() as client:
            res = await client.post(api_url, json=payload, timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                if "matches" in data:
                    threats = [match.get("threatType") for match in data["matches"]]
                    return {"matches": True, "threats": threats}
    except Exception as e:
        error_logger.error(f"Google Safe Browsing query failed for {url}", e)
    return {"matches": False, "threats": []}

async def query_urlscan(domain: str) -> dict:
    """Queries the URLScan.io search API for historical malicious detections of the domain."""
    if not settings.urlscan_api_key:
        return {"malicious": False, "score": 0}
    try:
        api_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        headers = {"API-Key": settings.urlscan_api_key}
        async with httpx.AsyncClient() as client:
            res = await client.get(api_url, headers=headers, timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", [])
                malicious_hits = 0
                for r in results:
                    stats = r.get("stats", {})
                    if stats.get("malicious", 0) > 0:
                        malicious_hits += 1
                return {"malicious": malicious_hits > 0, "score": min(100, malicious_hits * 25)}
    except Exception as e:
        error_logger.error(f"URLScan.io query failed for domain: {domain}", e)
    return {"malicious": False, "score": 0}

async def query_abuseipdb(ip: str) -> dict:
    """Queries the AbuseIPDB v2 API for the resolved domain IP reputation."""
    if not settings.abuseipdb_key or not ip:
        return {"abuse_score": 0, "reports": 0}
    try:
        api_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": settings.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        async with httpx.AsyncClient() as client:
            res = await client.get(api_url, headers=headers, params=params, timeout=5.0)
            if res.status_code == 200:
                data = res.json().get("data", {})
                return {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "reports": data.get("totalReports", 0)
                }
    except Exception as e:
        error_logger.error(f"AbuseIPDB query failed for IP: {ip}", e)
    return {"abuse_score": 0, "reports": 0}

async def query_virustotal(url: str) -> dict:
    """Queries the VirusTotal v3 API for URL scanner hits."""
    if not settings.virustotal_api_key:
        return {"malicious": 0, "total": 0}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": settings.virustotal_api_key}
        async with httpx.AsyncClient() as client:
            res = await client.get(api_url, headers=headers, timeout=5.0)
            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                return {"malicious": stats.get("malicious", 0), "total": sum(stats.values())}
    except Exception as e:
        error_logger.error(f"VirusTotal query failed for URL: {url}", e)
    return {"malicious": 0, "total": 0}

async def resolve_domain_ip(domain: str) -> Optional[str]:
    """Performs local DNS lookup to resolve domain hostname to an IP address asynchronously."""
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except Exception:
        return None

async def query_unified_intel(url: str, domain: str) -> dict:
    """
    Consolidates API reputation checks (Google Safe Browsing, URLScan, AbuseIPDB, VirusTotal)
    using asynchronous lookups and local threat intelligence database caching.
    """
    # 1. Check Threat Cache
    cached_data = get_threat_intel_cache(domain)
    if cached_data:
        return cached_data

    # 2. Resolve IP for AbuseIPDB
    ip = await resolve_domain_ip(domain)
    
    # 3. Perform Concurrent Lookups
    vt_task = query_virustotal(url)
    gsb_task = query_google_safe_browsing(url)
    urlscan_task = query_urlscan(domain)
    abuseipdb_task = query_abuseipdb(ip)
    
    vt_res, gsb_res, urlscan_res, abuse_res = await asyncio.gather(
        vt_task, gsb_task, urlscan_task, abuseipdb_task, return_exceptions=True
    )
    
    # Secure fallbacks on gather exceptions
    vt_data = vt_res if not isinstance(vt_res, Exception) else {"malicious": 0, "total": 0}
    gsb_data = gsb_res if not isinstance(gsb_res, Exception) else {"matches": False, "threats": []}
    urlscan_data = urlscan_res if not isinstance(urlscan_res, Exception) else {"malicious": False, "score": 0}
    abuse_data = abuse_res if not isinstance(abuse_res, Exception) else {"abuse_score": 0, "reports": 0}
    
    # Check local/OpenPhish feeds (zero latency check)
    openphish_match = (url in intel_db.malicious_urls) or (domain in intel_db.malicious_urls)

    unified_results = {
        "domain": domain,
        "resolved_ip": ip or "0.0.0.0",
        "virustotal": vt_data,
        "safe_browsing": gsb_data,
        "urlscan": urlscan_data,
        "abuseipdb": abuse_data,
        "openphish": {
            "matches": openphish_match,
            "source": "OpenPhish & Local Feeds"
        },
        "summary": {
            "threat_signals": (
                (1 if gsb_data.get("matches") else 0) +
                (1 if vt_data.get("malicious", 0) > 2 else 0) +
                (1 if urlscan_data.get("malicious") else 0) +
                (1 if abuse_data.get("abuse_score", 0) > 30 else 0) +
                (1 if openphish_match else 0)
            )
        }
    }
    
    # 4. Save to Cache
    set_threat_intel_cache(domain, unified_results)
    
    return unified_results
