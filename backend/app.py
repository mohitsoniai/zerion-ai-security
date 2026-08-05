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
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WADE Command Center - Web AI Defense Engine</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-dark: #030308;
                --panel-bg: rgba(10, 10, 16, 0.7);
                --cyan: #00f3ff;
                --cyan-glow: rgba(0, 243, 255, 0.4);
                --red: #ff003c;
                --red-glow: rgba(255, 0, 60, 0.4);
                --green: #00ff66;
                --orange: #ffa500;
                --text-main: #f0f0f5;
                --text-muted: #8e90a6;
                --font-primary: 'Space Grotesk', sans-serif;
                --font-secondary: 'Outfit', sans-serif;
            }

            body {
                background-color: var(--bg-dark);
                background-image: 
                    radial-gradient(circle at 50% 0%, rgba(0, 243, 255, 0.1) 0%, transparent 50%),
                    linear-gradient(rgba(255, 255, 255, 0.01) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255, 255, 255, 0.01) 1px, transparent 1px);
                background-size: 100% 100%, 40px 40px, 40px 40px;
                color: var(--text-main);
                font-family: var(--font-primary);
                margin: 0;
                padding: 30px;
                min-height: 100vh;
                box-sizing: border-box;
            }

            .container {
                max-width: 1400px;
                margin: 0 auto;
            }

            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid rgba(0, 243, 255, 0.2);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .logo-area h1 {
                margin: 0;
                font-family: var(--font-secondary);
                font-weight: 800;
                font-size: 32px;
                letter-spacing: 2px;
                color: #fff;
                text-shadow: 0 0 10px var(--cyan-glow);
            }
            .logo-area h1 span {
                color: var(--cyan);
            }
            .logo-area p {
                margin: 5px 0 0 0;
                font-size: 14px;
                color: var(--text-muted);
            }

            .sys-state {
                display: flex;
                align-items: center;
                gap: 10px;
                background: rgba(0, 255, 102, 0.1);
                border: 1px solid var(--green);
                padding: 8px 16px;
                border-radius: 30px;
                color: var(--green);
                font-weight: bold;
                font-size: 13px;
                text-shadow: 0 0 5px rgba(0, 255, 102, 0.3);
                box-shadow: 0 0 10px rgba(0, 255, 102, 0.1);
            }
            .dot {
                width: 8px;
                height: 8px;
                background-color: var(--green);
                border-radius: 50%;
                animation: pulse 1.5s infinite;
            }
            @keyframes pulse {
                0% { transform: scale(0.9); opacity: 0.6; }
                50% { transform: scale(1.2); opacity: 1; }
                100% { transform: scale(0.9); opacity: 0.6; }
            }

            /* Stats grid */
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .card {
                background: var(--panel-bg);
                backdrop-filter: blur(15px);
                border: 1px solid rgba(0, 243, 255, 0.1);
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                transition: transform 0.3s, border-color 0.3s, box-shadow 0.3s;
                position: relative;
                overflow: hidden;
            }
            .card:hover {
                transform: translateY(-5px);
                border-color: rgba(0, 243, 255, 0.3);
                box-shadow: 0 12px 40px rgba(0, 243, 255, 0.15);
            }
            .card h3 {
                margin: 0 0 12px 0;
                font-family: var(--font-secondary);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: var(--text-muted);
            }
            .card .val {
                font-size: 42px;
                font-weight: 700;
                color: #fff;
                text-shadow: 0 0 15px var(--cyan-glow);
            }

            /* Donut card layout */
            .donut-layout {
                display: flex;
                align-items: center;
                gap: 24px;
            }
            .donut-chart-container {
                position: relative;
                width: 90px;
                height: 90px;
            }
            .donut {
                width: 100%;
                height: 100%;
                border-radius: 50%;
                background: conic-gradient(#333 0% 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: inset 0 0 8px rgba(0, 0, 0, 0.5);
            }
            .donut-hole {
                width: 64px;
                height: 64px;
                background-color: #0b0b14;
                border-radius: 50%;
                position: absolute;
            }

            .legend {
                display: flex;
                flex-direction: column;
                gap: 8px;
                font-size: 12px;
            }
            .legend-item {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .box {
                width: 12px;
                height: 12px;
                border-radius: 3px;
            }

            /* Analytics grid */
            .analytics-grid {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 25px;
                margin-bottom: 30px;
            }
            @media (max-width: 992px) {
                .analytics-grid { grid-template-columns: 1fr; }
            }

            .chart-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            .chart-header h2 {
                margin: 0;
                font-size: 18px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: var(--cyan);
                text-shadow: 0 0 5px var(--cyan-glow);
            }
            .tabs {
                display: flex;
                background: rgba(0, 0, 0, 0.3);
                padding: 4px;
                border-radius: 8px;
                border: 1px solid rgba(255, 255, 255, 0.05);
            }
            .tab-btn {
                background: transparent;
                border: none;
                color: var(--text-muted);
                padding: 6px 14px;
                font-family: inherit;
                font-size: 11px;
                font-weight: 600;
                cursor: pointer;
                border-radius: 6px;
                text-transform: uppercase;
                transition: 0.2s;
            }
            .tab-btn.active {
                background: var(--cyan);
                color: #000;
                box-shadow: 0 0 8px var(--cyan);
            }

            .progress-list {
                display: flex;
                flex-direction: column;
                gap: 15px;
            }
            .progress-row {
                display: flex;
                flex-direction: column;
                gap: 6px;
            }
            .progress-row-label {
                display: flex;
                justify-content: space-between;
                font-size: 12px;
            }
            .bar-bg {
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.05);
                height: 8px;
                border-radius: 4px;
                overflow: hidden;
                width: 100%;
            }
            .bar-fill {
                height: 100%;
                border-radius: 4px;
                transition: width 0.4s ease;
            }

            /* Log panel section */
            .logs-panel {
                margin-bottom: 40px;
            }
            .logs-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 20px;
            }
            .logs-header h2 {
                margin: 0;
                font-size: 20px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: #fff;
            }
            .search-filter-area {
                display: flex;
                gap: 12px;
                align-items: center;
                flex-wrap: wrap;
            }
            .search-input {
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(0, 243, 255, 0.15);
                border-radius: 8px;
                padding: 8px 16px;
                color: #fff;
                font-family: inherit;
                font-size: 13px;
                outline: none;
                width: 250px;
                transition: 0.3s;
            }
            .search-input:focus {
                border-color: var(--cyan);
                box-shadow: 0 0 10px var(--cyan-glow);
            }
            select {
                background: #0d0d18;
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: var(--text-main);
                padding: 8px 12px;
                border-radius: 8px;
                font-family: inherit;
                font-size: 12px;
                cursor: pointer;
                outline: none;
                transition: 0.3s;
            }
            select:focus {
                border-color: var(--cyan);
            }

            .export-btn {
                background: transparent;
                border: 1px solid var(--cyan);
                color: var(--cyan);
                padding: 8px 16px;
                border-radius: 8px;
                font-family: inherit;
                font-size: 12px;
                font-weight: 600;
                cursor: pointer;
                transition: 0.2s;
                text-transform: uppercase;
            }
            .export-btn:hover {
                background: var(--cyan);
                color: #000;
                box-shadow: 0 0 12px var(--cyan);
            }

            table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0 8px;
                margin-top: 10px;
            }
            th, td {
                padding: 14px 18px;
                text-align: left;
                font-size: 13px;
            }
            th {
                color: var(--text-muted);
                font-size: 11px;
                text-transform: uppercase;
                font-weight: 700;
                letter-spacing: 1px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
            tbody tr {
                background: rgba(255, 255, 255, 0.01);
                border: 1px solid rgba(255, 255, 255, 0.02);
                border-radius: 12px;
                transition: all 0.2s ease;
            }
            tbody tr:hover {
                background: rgba(0, 243, 255, 0.05);
                transform: translateX(4px);
                box-shadow: -4px 0 0 var(--cyan);
            }

            .badge {
                padding: 5px 10px;
                border-radius: 6px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
                display: inline-block;
            }
            .badge.safe { background: rgba(0, 255, 102, 0.1); color: var(--green); border: 1px solid var(--green); }
            .badge.warn { background: rgba(255, 165, 0, 0.1); color: var(--orange); border: 1px solid var(--orange); }
            .badge.danger { background: rgba(255, 0, 60, 0.1); color: var(--red); border: 1px solid var(--red); }

            .empty-state {
                text-align: center;
                padding: 40px;
                color: var(--text-muted);
                font-style: italic;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo-area">
                    <h1>🛡️ WADE<span>.AI</span> v2</h1>
                    <p>Web AI Defense Engine & Threat Command Center</p>
                </div>
                <div class="sys-state">
                    <div class="dot"></div>
                    SYSTEM INTEGRITY: ACTIVE
                </div>
            </div>

            <!-- Stats aggregates -->
            <div class="stats-grid">
                <div class="card">
                    <h3>Total Scans Intercepted</h3>
                    <div class="val" id="stat-total">0</div>
                </div>
                <div class="card">
                    <h3>Security Success Rate</h3>
                    <div class="val" id="stat-rate" style="color: var(--green);">100%</div>
                </div>
                <div class="card">
                    <h3>Threats Blocked</h3>
                    <div class="val" id="stat-blocked" style="color: var(--red);">0</div>
                </div>
                <div class="card">
                    <h3>Risk Distribution</h3>
                    <div class="donut-layout">
                        <div class="donut-chart-container">
                            <div class="donut" id="donut-chart">
                                <div class="donut-hole"></div>
                            </div>
                        </div>
                        <div class="legend">
                            <div class="legend-item"><div class="box" style="background: var(--green);"></div>Safe (<span id="lg-safe">0</span>)</div>
                            <div class="legend-item"><div class="box" style="background: var(--orange);"></div>Suspicious (<span id="lg-warn">0</span>)</div>
                            <div class="legend-item"><div class="box" style="background: var(--red);"></div>Blocked (<span id="lg-danger">0</span>)</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Charts and timeline -->
            <div class="analytics-grid">
                <div class="card">
                    <div class="chart-header">
                        <h2>Threat Interception Timeline</h2>
                        <div class="tabs">
                            <button class="tab-btn active" onclick="switchTimeline('daily')">Daily</button>
                            <button class="tab-btn" onclick="switchTimeline('weekly')">Weekly</button>
                            <button class="tab-btn" onclick="switchTimeline('monthly')">Monthly</button>
                        </div>
                    </div>
                    <div id="timeline-chart" style="min-height: 180px; display: flex; align-items: center; justify-content: center;">
                        <!-- Rendered by JS -->
                    </div>
                </div>

                <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
                    <div>
                        <div class="chart-header">
                            <h2>Threat Categories</h2>
                        </div>
                        <div class="progress-list" id="cat-list">
                            <!-- Rendered by JS -->
                        </div>
                    </div>
                    <div style="margin-top: 20px;">
                        <div class="chart-header">
                            <h2>Severity Levels</h2>
                        </div>
                        <div class="progress-list" id="sev-list">
                            <!-- Rendered by JS -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- Logs section -->
            <div class="card logs-panel">
                <div class="logs-header">
                    <h2>📡 Threat Audit History Logs</h2>
                    <div class="search-filter-area">
                        <input type="text" id="search-bar" class="search-input" placeholder="Search target URL..." oninput="filterLogs()">
                        <select id="filter-verdict" onchange="filterLogs()">
                            <option value="ALL">All Verdicts</option>
                            <option value="SAFE">Safe</option>
                            <option value="SUSPICIOUS">Suspicious</option>
                            <option value="MALICIOUS">Blocked</option>
                        </select>
                        <select id="filter-severity" onchange="filterLogs()">
                            <option value="ALL">All Severities</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Informational">Informational</option>
                        </select>
                        <button class="export-btn" onclick="exportData('csv')">CSV</button>
                        <button class="export-btn" onclick="exportData('json')">JSON</button>
                    </div>
                </div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Target URL</th>
                                <th>Verdict</th>
                                <th>Risk Score</th>
                                <th>Severity</th>
                                <th>Detection Reason</th>
                            </tr>
                        </thead>
                        <tbody id="logs-body">
                            <!-- Populated by JS -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            let cachedStats = {};
            let recentScans = [];

            async function loadDashboard() {
                try {
                    // Fetch stats
                    const statsResp = await fetch('/dashboard/stats');
                    cachedStats = await statsResp.json();
                    
                    // Fetch recent scans
                    const scansResp = await fetch('/dashboard/recent');
                    recentScans = await scansResp.json();
                    
                    updateStatsDOM();
                    switchTimeline('weekly');
                    updateLogsTable(recentScans);
                } catch (e) {
                    console.error("Dashboard loading error", e);
                }
            }

            function updateStatsDOM() {
                if (!cachedStats) return;
                
                document.getElementById('stat-total').innerText = cachedStats.total_scans || 0;
                document.getElementById('stat-rate').innerText = (cachedStats.success_rate || 100) + '%';
                document.getElementById('stat-blocked').innerText = cachedStats.phishing || 0;
                
                // Donut chart text counts
                document.getElementById('lg-safe').innerText = cachedStats.safe || 0;
                document.getElementById('lg-warn').innerText = cachedStats.suspicious || 0;
                document.getElementById('lg-danger').innerText = cachedStats.phishing || 0;
                
                // Donut style calculation
                const total = cachedStats.total_scans || 1;
                const safePct = ((cachedStats.safe || 0) / total) * 100;
                const susPct = ((cachedStats.suspicious || 0) / total) * 100;
                
                const donut = document.getElementById('donut-chart');
                donut.style.background = `conic-gradient(
                    var(--green) 0% ${safePct}%, 
                    var(--orange) ${safePct}% ${safePct + susPct}%, 
                    var(--red) ${safePct + susPct}% 100%
                )`;

                // Render Threat Categories
                const catList = document.getElementById('cat-list');
                catList.innerHTML = '';
                const categories = cachedStats.categories || {};
                const catColors = { 'Safe': 'var(--green)', 'Phishing': 'var(--red)', 'Malware': '#a500ff', 'XSS': 'var(--orange)', 'Social Engineering': 'var(--cyan)' };
                
                for (const cat in categories) {
                    const cnt = categories[cat];
                    const pct = ((cnt / total) * 100).toFixed(0);
                    const color = catColors[cat] || 'var(--cyan)';
                    catList.innerHTML += `
                        <div class="progress-row">
                            <div class="progress-row-label">
                                <span>${cat}</span>
                                <span style="color: ${color}; font-weight: bold;">${cnt} (${pct}%)</span>
                            </div>
                            <div class="bar-bg">
                                <div class="bar-fill" style="width: ${pct}%; background-color: ${color};"></div>
                            </div>
                        </div>
                    `;
                }

                // Render Severities
                const sevList = document.getElementById('sev-list');
                sevList.innerHTML = '';
                const severities = cachedStats.severities || {};
                const sevColors = { 'Critical': 'var(--red)', 'High': 'var(--orange)', 'Medium': '#ffff00', 'Low': '#00ffc4', 'Informational': 'var(--green)' };
                
                for (const sev in severities) {
                    const cnt = severities[sev];
                    const pct = ((cnt / total) * 100).toFixed(0);
                    const color = sevColors[sev] || 'var(--cyan)';
                    sevList.innerHTML += `
                        <div class="progress-row">
                            <div class="progress-row-label">
                                <span>${sev}</span>
                                <span style="color: ${color}; font-weight: bold;">${cnt} (${pct}%)</span>
                            </div>
                            <div class="bar-bg">
                                <div class="bar-fill" style="width: ${pct}%; background-color: ${color};"></div>
                            </div>
                        </div>
                    `;
                }
            }

            function switchTimeline(period) {
                // Update active tab button style
                document.querySelectorAll('.tab-btn').forEach(btn => {
                    btn.classList.toggle('active', btn.innerText.toLowerCase() === period);
                });
                
                let data = [];
                if (period === 'daily') data = cachedStats.timeline_daily || [];
                else if (period === 'weekly') data = cachedStats.timeline_weekly || [];
                else if (period === 'monthly') data = cachedStats.timeline_monthly || [];
                
                const container = document.getElementById('timeline-chart');
                if (data.length === 0) {
                    container.innerHTML = '<div class="empty-state">No timeline logs found for this range.</div>';
                    return;
                }
                
                const maxVal = Math.max(...data.map(d => d.count), 1);
                let html = '<div style="display: flex; align-items: flex-end; justify-content: space-around; height: 140px; width: 100%;">';
                
                data.forEach(item => {
                    const height = (item.count / maxVal) * 100;
                    // Format daily labels for better output
                    let label = item.label;
                    if (period === 'weekly' || period === 'monthly') {
                        const pts = label.split('-');
                        if (pts.length >= 3) label = pts[1] + '/' + pts[2];
                    }
                    html += `
                        <div style="display: flex; flex-direction: column; align-items: center; flex: 1;">
                            <span style="font-size: 10px; color: #fff; margin-bottom: 4px; text-shadow: 0 0 5px var(--cyan-glow);">${item.count}</span>
                            <div class="bar-fill" style="height: ${height}px; width: 14px; background: linear-gradient(to top, rgba(0,243,255,0.1), var(--cyan)); border-radius: 3px 3px 0 0; box-shadow: 0 0 8px var(--cyan-glow);"></div>
                            <span style="font-size: 8px; color: var(--text-muted); margin-top: 6px; white-space: nowrap; transform: rotate(-20deg);">${label}</span>
                        </div>
                    `;
                });
                html += '</div>';
                container.innerHTML = html;
            }

            function updateLogsTable(scans) {
                const body = document.getElementById('logs-body');
                body.innerHTML = '';
                
                if (scans.length === 0) {
                    body.innerHTML = '<tr><td colspan="6" class="empty-state">No scans logged matching filters.</td></tr>';
                    return;
                }
                
                scans.forEach(scan => {
                    const tr = document.createElement('tr');
                    
                    let badgeClass = 'safe';
                    if (scan.verdict === 'MALICIOUS') badgeClass = 'danger';
                    else if (scan.verdict === 'SUSPICIOUS') badgeClass = 'warn';
                    
                    const scoreColor = scan.risk_score > 75 ? 'var(--red)' : scan.risk_score > 30 ? 'var(--orange)' : 'var(--green)';
                    const displayUrl = scan.url.length > 55 ? scan.url.substring(0, 55) + '...' : scan.url;
                    
                    tr.innerHTML = `
                        <td style="color: var(--text-muted);">${scan.timestamp}</td>
                        <td title="${scan.url}" style="font-weight: 600;">${displayUrl}</td>
                        <td><span class="badge ${badgeClass}">${scan.verdict}</span></td>
                        <td style="color: ${scoreColor}; font-weight: bold; text-shadow: 0 0 5px rgba(255,255,255,0.1);">${scan.risk_score}</td>
                        <td style="font-weight: 500;">${scan.severity || 'Informational'}</td>
                        <td style="color: var(--text-muted); font-size: 12px;">${scan.detection_reason || 'N/A'}</td>
                    `;
                    body.appendChild(tr);
                });
            }

            function filterLogs() {
                const searchQ = document.getElementById('search-bar').value.toLowerCase().trim();
                const verdictF = document.getElementById('filter-verdict').value;
                const severityF = document.getElementById('filter-severity').value;
                
                const filtered = recentScans.filter(scan => {
                    if (searchQ && !scan.url.toLowerCase().includes(searchQ)) return false;
                    if (verdictF !== 'ALL' && scan.verdict !== verdictF) return false;
                    if (severityF !== 'ALL' && scan.severity !== severityF) return false;
                    return true;
                });
                
                updateLogsTable(filtered);
            }

            function exportData(format) {
                if (recentScans.length === 0) return alert("No logs available to export.");
                
                if (format === 'csv') {
                    const headers = ['Timestamp', 'URL', 'Verdict', 'Risk Score', 'Severity', 'Detection Reason'];
                    const rows = recentScans.map(scan => [
                        scan.timestamp,
                        `"${scan.url.replace(/"/g, '""')}"`,
                        scan.verdict,
                        scan.risk_score,
                        scan.severity || 'Informational',
                        `"${(scan.detection_reason || '').replace(/"/g, '""')}"`
                    ]);
                    
                    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\\n');
                    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                    triggerDownload(blob, `wade_logs_${new Date().toISOString().split('T')[0]}.csv`);
                } else if (format === 'json') {
                    const json = JSON.stringify(recentScans, null, 2);
                    const blob = new Blob([json], { type: 'application/json;charset=utf-8;' });
                    triggerDownload(blob, `wade_logs_${new Date().toISOString().split('T')[0]}.json`);
                }
            }

            function triggerDownload(blob, filename) {
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.setAttribute('href', url);
                link.setAttribute('download', filename);
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }

            window.onload = loadDashboard;
        </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="0.0.0.0", port=7860, reload=True)