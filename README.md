# Zerion AI v2 🛡️ (AI-Powered Browser Security Platform)

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/mohitsoniai/Zerion AI-AI-extension)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Status](https://img.shields.io/badge/status-Stable-success)](#status)
[![Platform](https://img.shields.io/badge/platform-Chrome--Extension-orange.svg)](#installation)
[![Docker](https://img.shields.io/badge/docker-verified-blue.svg)](#docker-container-quickstart)

Zerion AI v2 (AI-Powered Browser Security Platform) is a next-generation, AI-powered browser security platform designed to identify, analyze, and neutralize sophisticated web-based threats in real-time. Traditional security solutions rely on static blacklists, leaving users vulnerable to zero-day phishing campaigns, credential harvesting, and obfuscated malicious scripts.

Zerion AI v2 solves this by integrating **multi-provider Threat Intelligence** (AbuseIPDB, Google Safe Browsing, URLScan, VirusTotal, OpenPhish), **dual Large Language Model (LLM)** intent audits, and local SQLite caches to deliver subsecond verdicts with zero-trust execution.

> [!IMPORTANT]
> **Open Architecture:** This platform is fully open and does not require account creation, passwords, logins, or API keys for browser interaction. The extension and backend function out-of-the-box immediately upon installation.

---

## 🏗️ Architecture Overview

Zerion AI v2 follows a **Service-Oriented Architecture (SOA)** consisting of:

1. **The Eyes (Frontend):** A Manifest V3 Chrome Extension that tracks DOM changes, intercepts navigation events, and runs an out-of-band URL hover auditor.
2. **The Brain (Backend):** A FastAPI Python engine coordinating VirusTotal, Google Safe Browsing, AbuseIPDB, URLScan, and active phishing databases (URLHaus, OpenPhish).
3. **The Intelligence Layer (AI):** A dual-LLM pipeline utilizing **Groq (Llama 3.3 70B)** for intent analysis and **Google Gemini 1.5 Flash** for fallback classification.
4. **The Storage (Database):** A SQLite database tracking threat audit logs and keeping caches (`threat_intel_cache`, `api_cache`) to prevent rate-limit depletion.

For details, view the [docs/SYSTEM_ARCHITECTURE.md](file:///c:/Users/MOHIT%20SONI/Zerion AI-AI-Defense/docs/SYSTEM_ARCHITECTURE.md).

---

## 🚀 Key Features

* **Multi-Provider OSINT Orchestrator:** Live API evaluations via VirusTotal, Google Safe Browsing, AbuseIPDB, URLScan, OpenPhish, and URLHaus.
* **Unified AI Reasoning:** Returns advanced telemetry (Threat Score, Confidence rating, Category, Severity, Suspicious Indicators, WHOIS, and SSL summaries).
* **Advanced Command Center:** A glassmorphic management dashboard featuring timeline charts, filters, domain whitelist controls, and CSV/JSON exporters.
* **Modern Controls Popup:** Built-in dark mode popup supporting Auto-Scan toggling, manual Rescans, whitelist updates, and direct false-positive reporting.
* **IPS Real-Time Intervention:** Automatically interrupts high-risk connections and redirects to a secure warning block page.

---

## 🛠️ Tech Stack

* **AI Models:** Groq Llama 3.3 (70B), Google Gemini 1.5 Flash
* **Backend:** Python 3.10, FastAPI, Uvicorn, Async HTTPX, WHOIS & SSL Certificates Parser
* **Frontend:** Vanilla JS (ES6+), HTML5, CSS3 (Glassmorphism & 3D Tilt), Chrome Extension Manifest V3
* **Database:** SQLite3
* **DevOps:** Docker, Docker Compose, GitHub Actions

---

## 🗂️ Folder Structure

```
zerion-ai-defense/
├── .github/workflows/     # GitHub Actions
│   └── deploy.yml
├── docs/                  # System Architecture Portals
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── API_DOCUMENTATION.md
│   ├── ER_DIAGRAM.md
│   ├── DEPLOYMENT_DIAGRAM.md
│   └── DEPLOYMENT_GUIDE.md
├── backend/               # Modular FastAPI MVC App
│   ├── app.py             # App entry orchestrator
│   ├── config/            # Settings & pydantic configuration
│   ├── controllers/       # API router controllers
│   ├── database/          # SQLite models, caches, and migrations
│   ├── middlewares/       # Rate limiting & Helmet secure headers
│   ├── services/          # Threat Intel & AI Scanner engines
│   ├── utils/             # Loggers & WHOIS calculators
│   └── requirements.txt   # Backend requirements
├── extension/             # Chrome Extension MV3
│   ├── background.js      # Interceptor background worker
│   ├── blocked.html       # Intercept warning page
│   ├── dashboard.html     # Telemetry management console
│   ├── popup.html         # Custom popup panel
│   └── icons/             # Graphical assets
├── Dockerfile             # Multi-stage production container
└── docker-compose.yml     # Compose script
```

---

## 📦 Installation & Setup

Please follow the detailed [docs/DEPLOYMENT_GUIDE.md](file:///c:/Users/MOHIT%20SONI/Zerion AI-AI-Defense/docs/DEPLOYMENT_GUIDE.md) to set up Zerion AI v2.

### Quick Start (Local Backend):

```bash
# Clone the repository
git clone https://github.com/mohitsoniai/Zerion AI-AI-extension.git
cd Zerion AI-AI-Defense

# Configure environment variables
cp .env.example .env
# Edit .env and supply your Google Gemini, Groq, and OSINT API keys

# Setup Python Virtual Environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r backend/requirements.txt

# Run FastAPI server
python -m backend.app
```

### Docker Container Quickstart:

```bash
# Spin up the containers using Compose
docker-compose up --build
```
The server will start running on port `7860`. You can access the Web Command Center Dashboard at `http://localhost:7860/` and verify server health status at `http://localhost:7860/health`.

### ☁️ Cloud Deployments:
* **Render:** Blueprinted automatically via [render.yaml](file:///c:/Users/MOHIT%20SONI/Zerion AI-AI-Defense/render.yaml).
* **Vercel:** Bypassed and hosted using serverless rules in [vercel.json](file:///c:/Users/MOHIT%20SONI/Zerion AI-AI-Defense/vercel.json).

### GitHub Recommended Topics
`chrome-extension`, `fastapi`, `cybersecurity`, `artificial-intelligence`, `phishing-detection`, `threat-intelligence`, `docker`
