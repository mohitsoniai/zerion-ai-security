# WADE AI v2 - Deployment Diagram

This document details the target cloud deployment and local installation boundaries for WADE AI v2.

---

## 🚀 Cloud Deployment Layout

WADE AI v2 features a completely decoupled architecture, allowing the extension client to interact directly with any hosted Docker container instances.

```mermaid
graph TD
    subgraph Client Endpoint (Client Host)
        Ext[WADE Chrome Extension MV3]
        LocalCache[(Local HTML5 storage)]
        Ext <--> LocalCache
    end

    subgraph CDN & Repository Portals
        ChromeStore[Chrome Web Store CDN]
        Github[GitHub Actions Repo]
    end

    subgraph Production Cloud Boundaries (VPS / Containers)
        DockerHost[Docker Runner Container]
        FastAPI[FastAPI Server App]
        SqliteDB[(Local SQLite wade_logs.db)]
        
        DockerHost --> FastAPI
        FastAPI <--> SqliteDB
    end

    subgraph External Intelligence & LLMs
        VT[VirusTotal / AbuseIPDB APIs]
        LLM[Groq / Gemini AI APIs]
    end

    ChromeStore -.->|Install/Update| Ext
    Github -.->|CI CD trigger build| DockerHost
    
    Ext <-->|HTTPS REST Request - No Auth| FastAPI
    FastAPI <-->|OSINT lookup| VT
    FastAPI <-->|Classification JSON| LLM
```

---

## 📦 Container Hosting Configurations

### 1. Docker Compose Integration
To run the entire system locally:
```bash
docker-compose up --build
```
This starts the backend API service on port `7860`, reading settings dynamically from `.env` or system variables.

### 2. Render / Vercel Deployments
* **Vercel Serverless Hosting:** The project is configured with a root [vercel.json](file:///c:/Users/MOHIT%20SONI/WADE-AI-Defense/vercel.json) configuration mapping the FastAPI app. Deploy directly to Vercel via:
  ```bash
  npm i -g vercel
  vercel
  ```
* **Render Service Deployments:** Render builds the backend using the root [render.yaml](file:///c:/Users/MOHIT%20SONI/WADE-AI-Defense/render.yaml) infrastructure spec which exposes port `7860`.
* **Hugging Face Spaces:** Can be hosted as a **Docker Space**. Hugging Face mounts the exposed port `7860` automatically.
