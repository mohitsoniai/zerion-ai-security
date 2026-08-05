# WADE AI v2 - API Documentation

WADE AI v2 exposes a RESTful API powered by FastAPI. This API handles real-time threat intelligence gathering, machine learning-based risk score calculations, and system statistics logs.

---

## 📡 Base URL
When running locally: `http://localhost:7860`
When deployed on Hugging Face Spaces: `https://<your-space-name>.hf.space`

---

## 🔒 Authentication & Headers
WADE AI v2 operates fully **open access**. 
No authentication header (`X-WADE-API-KEY`) or login credentials are required to communicate with endpoints. The application is ready to use immediately upon client installation.

---

## 🛣️ API Endpoints

### 1. Analyze URL
Analyzes a URL for potential phishing, malware, or script-based exploits using active threat feeds, domain age records, VirusTotal engine count, AbuseIPDB IP reputation, Google Safe Browsing matches, URLScan lookups, and AI judgment.

* **URL:** `/analyze`
* **Method:** `POST`
* **Content-Type:** `application/json`

#### Request Body Schema
```json
{
  "url": "string (Required. The absolute URL to inspect)",
  "username": "string (Optional. Default: 'Anonymous')"
}
```

#### Example Request
```bash
curl -X POST "http://localhost:7860/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://wicar.org/test-malware"}'
```

#### Response Fields
* `threat_score` (integer, 0-100): The composite risk score.
* `risk_score` (integer, 0-100): Alias of threat_score for dashboard compatibility.
* `verdict` (string): Either `"SAFE"` or `"MALICIOUS"`.
* `confidence_score` (integer, 0-100): Model estimation confidence.
* `explanation` (string): AI explanation detail.
* `threat_category` (string): Category (e.g. `"Phishing"`, `"Malware"`, `"XSS"`, `"Social Engineering"`, `"Safe"`).
* `severity` (string): Level (e.g. `"Informational"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"`).
* `detection_reason` (string): Trigger descriptor.
* `threat_labels` (array of strings): Tags list.
* `suspicious_indicators` (array of strings): Detected threat heuristic codes.
* `domain_reputation` (string): Summary description.
* `whois_summary` (string): Registration overview.
* `ssl_analysis` (string): Certificate check verdict.
* `recommendations` (string): Mitigation tips.
* `false_positive_probability` (float): Error score (0.0 to 100.0).
* `domain_age` (integer): Days or `-1`.
* `intel_data` (object): Unified API logs containing GSB, URLScan, VT, and AbuseIPDB ranges.

#### Example Response
```json
{
  "threat_score": 85,
  "risk_score": 85,
  "verdict": "MALICIOUS",
  "confidence_score": 95,
  "explanation": "Simulated sandbox override triggered for threat testing payload.",
  "threat_category": "Malware",
  "risk_category": "Malware",
  "severity": "Critical",
  "detection_reason": "Malware Testing Payload Detected",
  "threat_labels": ["test-payload", "sandbox-override"],
  "suspicious_indicators": ["eicar-signature-found"],
  "domain_reputation": "Hostile (Demo)",
  "whois_summary": "Active phishing link.",
  "ssl_analysis": "Suspicious",
  "recommendations": "Terminate connection immediately.",
  "false_positive_probability": 0.0,
  "domain_age": -1,
  "intel_data": {
    "domain": "wicar.org",
    "resolved_ip": "127.0.0.1",
    "virustotal": {"malicious": 12, "total": 89},
    "safe_browsing": {"matches": true, "threats": ["MALWARE"]},
    "urlscan": {"malicious": true, "score": 75},
    "abuseipdb": {"abuse_score": 15, "reports": 5}
  }
}
```

---

### 2. Dashboard Statistics
Returns aggregated counts, timelines, and categories from SQLite.

* **URL:** `/dashboard/stats`
* **Method:** `GET`

#### Example Request
```bash
curl -X GET "http://localhost:7860/dashboard/stats"
```

---

### 3. Recent Scans Log
Fetches list of the 20 most recent threat evaluations.

* **URL:** `/dashboard/recent`
* **Method:** `GET`

#### Example Request
```bash
curl -X GET "http://localhost:7860/dashboard/recent"
```

---

### 4. Quick Threat Report
Submits user-reported false positives or unblocked threats to the database.

* **URL:** `/report`
* **Method:** `POST`
* **Content-Type:** `application/json`

#### Request Body Schema
```json
{
  "domain": "string (Required. The domain to report)",
  "report_type": "string (Required. Either 'false_positive' or 'phishing')",
  "comment": "string (Optional. Extra comments)"
}
```

#### Example Request
```bash
curl -X POST "http://localhost:7860/report" \
     -H "Content-Type: application/json" \
     -d '{"domain": "safe-domain.com", "report_type": "false_positive", "comment": "This is my university site, please unblock."}'
```

#### Response Response
```json
{
  "success": true,
  "message": "Quick threat report logged successfully."
}
```

---

### 5. Health Check
Exposes container performance metrics and database states.

* **URL:** `/health`
* **Method:** `GET`

#### Example Response
```json
{
  "status": "healthy",
  "database": "connected",
  "threat_feeds_loaded": true,
  "threat_feeds_entries": 15482,
  "threat_intel_cache_size": 12,
  "api_cache_size": 47
}
```

---

## 🛠️ Errors & Handling

### 1. Rate Limit Exceeded (HTTP 429)
```json
{
  "detail": "Too many requests. Rate limit exceeded. Try again later."
}
```

### 2. Internal Server Error (HTTP 500)
```json
{
  "error": "InternalServerError",
  "message": "An unexpected error occurred while processing your request.",
  "details": "Traceback debug details..."
}
```
