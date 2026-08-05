import sqlite3
import json
from datetime import datetime, timedelta
from backend.config.settings import settings
from backend.utils.logger import error_logger, app_logger

# Define package initializer dynamically
def init_db() -> None:
    """Initializes the database schema with tables for logs, API caches, and Threat Intel caches."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            # 1. logs table (Threat History)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    sources TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    confidence_score INTEGER DEFAULT 0,
                    explanation TEXT,
                    risk_category TEXT,
                    severity TEXT,
                    detection_reason TEXT,
                    threat_labels TEXT,
                    suspicious_indicators TEXT,
                    domain_reputation TEXT,
                    whois_summary TEXT,
                    ssl_analysis TEXT,
                    recommendations TEXT,
                    false_positive_probability REAL DEFAULT 0.0
                )
            ''')
            
            # 2. threat_intel_cache table (Caching API results of VT, URLScan, Safe Browsing, AbuseIPDB)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    domain TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 3. api_cache table (Caching full API response payloads)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS api_cache (
                    url TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 4. statistics table (Caching aggregate counters)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    metric TEXT PRIMARY KEY,
                    value INTEGER DEFAULT 0
                )
            ''')
            
            # Prepopulate metrics if not present
            for metric in ['total_scans', 'safe', 'suspicious', 'phishing']:
                conn.execute("INSERT OR IGNORE INTO statistics (metric, value) VALUES (?, 0)", (metric,))

            # 5. threat_reports table (User-submitted quick threat reports)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    comment TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
        app_logger.info("Database schemas initialized successfully.")
    except Exception as e:
        error_logger.error("Failed to initialize database tables", e)

# Run initialization
init_db()

def log_threat_scan(url: str, result: dict, username: str = "Anonymous") -> None:
    """Inserts a scan record into the threat history logs database."""
    try:
        labels = result.get("threat_labels", [])
        labels_str = ",".join(labels) if isinstance(labels, list) else str(labels)
        
        indicators = result.get("suspicious_indicators", [])
        indicators_str = json.dumps(indicators) if isinstance(indicators, list) else str(indicators)

        with sqlite3.connect(settings.db_path) as conn:
            conn.execute(
                """
                INSERT INTO logs (
                    url, score, verdict, sources, username, confidence_score, explanation, 
                    risk_category, severity, detection_reason, threat_labels, 
                    suspicious_indicators, domain_reputation, whois_summary, 
                    ssl_analysis, recommendations, false_positive_probability
                ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    result.get("risk_score", 0),
                    result.get("verdict", "SAFE"),
                    "UnifiedEngine",
                    username,
                    result.get("confidence_score", result.get("risk_score", 0)),
                    result.get("explanation", ""),
                    result.get("risk_category", "Safe"),
                    result.get("severity", "Informational"),
                    result.get("detection_reason", "Audit Run"),
                    labels_str,
                    indicators_str,
                    result.get("domain_reputation", "Unknown"),
                    result.get("whois_summary", "Unresolved"),
                    result.get("ssl_analysis", "Unresolved"),
                    result.get("recommendations", "No warnings."),
                    float(result.get("false_positive_probability", 0.0))
                )
            )
            
            # Increment real-time cached statistics
            verdict = result.get("verdict", "SAFE").upper()
            metric_map = {"SAFE": "safe", "SUSPICIOUS": "suspicious", "MALICIOUS": "phishing"}
            metric = metric_map.get(verdict, "safe")
            conn.execute("UPDATE statistics SET value = value + 1 WHERE metric = 'total_scans'")
            conn.execute("UPDATE statistics SET value = value + 1 WHERE metric = ?", (metric,))
    except Exception as e:
        error_logger.error(f"Failed logging threat scan to DB for URL: {url}", e)

def log_threat_report(domain: str, report_type: str, comment: str) -> None:
    """Inserts a user-submitted threat report into the database."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute(
                "INSERT INTO threat_reports (domain, report_type, comment) VALUES (?, ?, ?)",
                (domain, report_type, comment)
            )
    except Exception as e:
        error_logger.error(f"Failed logging threat report for {domain}", e)

def get_threat_intel_cache(domain: str) -> dict | None:
    """Retrieves cached threat intelligence metrics for a domain if fresher than 12 hours."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT data, timestamp FROM threat_intel_cache WHERE domain = ?", (domain,)
            )
            row = cursor.fetchone()
            if row:
                ts = datetime.fromisoformat(row["timestamp"])
                # If cached within last 12 hours, return it
                if datetime.now() - ts < timedelta(hours=12):
                    return json.loads(row["data"])
    except Exception as e:
        error_logger.error(f"Error reading threat intel cache for {domain}", e)
    return None

def set_threat_intel_cache(domain: str, data: dict) -> None:
    """Caches threat intelligence query outputs for a domain."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_intel_cache (domain, data, timestamp)
                VALUES (?, ?, ?)
                """,
                (domain, json.dumps(data), datetime.now().isoformat())
            )
    except Exception as e:
        error_logger.error(f"Error writing threat intel cache for {domain}", e)

def get_api_cache(url: str) -> dict | None:
    """Retrieves cached API scan response for a URL if fresher than 4 hours."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT data, timestamp FROM api_cache WHERE url = ?", (url,)
            )
            row = cursor.fetchone()
            if row:
                ts = datetime.fromisoformat(row["timestamp"])
                # If cached within last 4 hours, return it
                if datetime.now() - ts < timedelta(hours=4):
                    return json.loads(row["data"])
    except Exception as e:
        error_logger.error(f"Error reading API cache for {url}", e)
    return None

def set_api_cache(url: str, data: dict) -> None:
    """Caches scan results for a URL to bypass repeated model lookups."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO api_cache (url, data, timestamp)
                VALUES (?, ?, ?)
                """,
                (url, json.dumps(data), datetime.now().isoformat())
            )
    except Exception as e:
        error_logger.error(f"Error writing API cache for {url}", e)

def get_db_stats() -> dict:
    """Compiles dashboard aggregates, daily/weekly/monthly timeline series, and severity volumes."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Read pre-calculated statistics
            cursor.execute("SELECT metric, value FROM statistics")
            stats = {row["metric"]: row["value"] for row in cursor.fetchall()}
            
            total = stats.get("total_scans", 0)
            safe = stats.get("safe", 0)
            phishing = stats.get("phishing", 0)
            suspicious = stats.get("suspicious", 0)
            
            # If the statistics table was empty or not updated yet, count directly from logs
            if total == 0:
                cursor.execute("SELECT verdict, COUNT(*) as cnt FROM logs GROUP BY verdict")
                verdicts = {row["verdict"]: row["cnt"] for row in cursor.fetchall()}
                safe = verdicts.get("SAFE", 0)
                phishing = verdicts.get("MALICIOUS", 0)
                suspicious = verdicts.get("SUSPICIOUS", 0)
                total = safe + phishing + suspicious
            
            # Severity volumes
            cursor.execute("SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity")
            severities = {row["severity"]: row["cnt"] for row in cursor.fetchall()}
            
            # Category volumes
            cursor.execute("SELECT risk_category, COUNT(*) as cnt FROM logs GROUP BY risk_category")
            categories = {row["risk_category"]: row["cnt"] for row in cursor.fetchall()}
            
            # Daily Timeline (Last 24 Hours)
            cursor.execute("""
                SELECT strftime('%H:00', timestamp) as scan_hour, COUNT(*) as cnt
                FROM logs
                WHERE timestamp >= datetime('now', '-1 day')
                GROUP BY scan_hour
                ORDER BY timestamp ASC
            """)
            timeline_daily = [{"label": row["scan_hour"], "count": row["cnt"]} for row in cursor.fetchall()]
            
            # Weekly Timeline (Last 7 Days)
            cursor.execute("""
                SELECT strftime('%Y-%m-%d', timestamp) as scan_date, COUNT(*) as cnt
                FROM logs
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY scan_date
                ORDER BY scan_date ASC
            """)
            timeline_weekly = [{"label": row["scan_date"], "count": row["cnt"]} for row in cursor.fetchall()]
            
            # Monthly Timeline (Last 30 Days)
            cursor.execute("""
                SELECT strftime('%Y-%m-%d', timestamp) as scan_date, COUNT(*) as cnt
                FROM logs
                WHERE timestamp >= datetime('now', '-30 days')
                GROUP BY scan_date
                ORDER BY scan_date ASC
            """)
            timeline_monthly = [{"label": row["scan_date"], "count": row["cnt"]} for row in cursor.fetchall()]
            
            success_rate = 100.0 if total == 0 else round((safe / total) * 100, 2)
            
            return {
                "total_scans": total,
                "safe": safe,
                "phishing": phishing,
                "suspicious": suspicious,
                "success_rate": success_rate,
                "severities": severities,
                "categories": categories,
                "timeline_daily": timeline_daily,
                "timeline_weekly": timeline_weekly,
                "timeline_monthly": timeline_monthly
            }
    except Exception as e:
        error_logger.error("Error reading database stats", e)
        return {
            "total_scans": 0,
            "safe": 0,
            "phishing": 0,
            "suspicious": 0,
            "success_rate": 100.0,
            "severities": {},
            "categories": {},
            "timeline_daily": [],
            "timeline_weekly": [],
            "timeline_monthly": []
        }

def get_recent_scans_logs(limit: int = 20) -> list[dict]:
    """Retrieves recent scan records from history database."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT id, url, score, verdict, timestamp, confidence_score, risk_category, 
                       severity, detection_reason, threat_labels, suspicious_indicators, 
                       domain_reputation, whois_summary, ssl_analysis, recommendations, 
                       false_positive_probability
                FROM logs 
                ORDER BY timestamp DESC 
                LIMIT {limit}
                """
            )
            scans = []
            for row in cursor.fetchall():
                try:
                    indicators = json.loads(row["suspicious_indicators"])
                except:
                    indicators = []
                scans.append({
                    "_id": row["id"],
                    "url": row["url"],
                    "risk_score": row["score"],
                    "verdict": row["verdict"],
                    "timestamp": row["timestamp"],
                    "confidence_score": row["confidence_score"],
                    "risk_category": row["risk_category"],
                    "severity": row["severity"],
                    "detection_reason": row["detection_reason"],
                    "threat_labels": row["threat_labels"].split(",") if row["threat_labels"] else [],
                    "suspicious_indicators": indicators,
                    "domain_reputation": row["domain_reputation"],
                    "whois_summary": row["whois_summary"],
                    "ssl_analysis": row["ssl_analysis"],
                    "recommendations": row["recommendations"],
                    "false_positive_probability": row["false_positive_probability"]
                })
            return scans
    except Exception as e:
        error_logger.error("Error retrieving recent logs from DB", e)
        return []

def log_threat_report(domain: str, report_type: str, comment: str) -> None:
    """Inserts a quick threat report from users into the database."""
    try:
        with sqlite3.connect(settings.db_path) as conn:
            conn.execute(
                "INSERT INTO threat_reports (domain, report_type, comment) VALUES (?, ?, ?)",
                (domain, report_type, comment)
            )
            app_logger.info(f"Recorded quick threat report for domain: {domain} ({report_type})")
    except Exception as e:
        error_logger.error(f"Failed logging threat report to DB for domain {domain}", e)
