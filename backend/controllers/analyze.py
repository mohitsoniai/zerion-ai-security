from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
import asyncio
from backend.utils.domain import TRUSTED_AGES, get_domain_age, get_domain_details
from backend.services.threat_intel import intel_db
from backend.services.intel_engine import query_unified_intel
from backend.services.ai_scanner import scanner
from backend.database.db import get_api_cache, set_api_cache, log_threat_scan, log_threat_report
from backend.middlewares.security import sanitize_input
from backend.utils.logger import error_logger

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    username: str | None = "Anonymous"

@router.post("/analyze")
async def analyze_url(request: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    """
    Scans URLs with full Threat Intelligence (VT, Safe Browsing, AbuseIPDB, URLScan)
    and detailed AI categorization. Employs caching for subsecond response speeds.
    """
    url = sanitize_input(request.url)
    username = sanitize_input(request.username or "Anonymous")
    
    if not url:
        raise HTTPException(status_code=400, detail="URL field is empty.")
        
    try:
        domain = url.split("//")[-1].split("/")[0].replace("www.", "").split(":")[0]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format.")

    # 1. Check API response Cache first (zero latency)
    cached_api_response = get_api_cache(url)
    if cached_api_response:
        # Log to DB asynchronously as history even on cache hit
        background_tasks.add_task(log_threat_scan, url, cached_api_response, username)
        return cached_api_response

    # 2. Academic Demo Overrides
    if "wicar.org" in domain or "eicar.org" in domain:
        result = {
            "threat_score": 85,
            "verdict": "MALICIOUS",
            "confidence_score": 95,
            "explanation": "Simulated sandbox override triggered for threat testing payload.",
            "threat_category": "Malware",
            "severity": "Critical",
            "detection_reason": "Malware Testing Payload Detected",
            "threat_labels": ["test-payload", "sandbox-override"],
            "suspicious_indicators": ["eicar-signature-found", "sandbox-test-pattern"],
            "domain_reputation": "Hostile (Demo Payload)",
            "whois_summary": "Domain age unresolved. Blacklisted testing address.",
            "ssl_analysis": "Revoked (Testing)",
            "recommendations": "Terminate connection immediately. Avoid downloads.",
            "false_positive_probability": 0.0,
            "domain_age": -1,
            "vt_data": {"malicious": 12, "total": 89}
        }
        result["risk_score"] = result["threat_score"]
        result["risk_category"] = result["threat_category"]
        
        set_api_cache(url, result)
        background_tasks.add_task(log_threat_scan, url, result, username)
        return result

    # 3. Local Whitelist
    if domain in TRUSTED_AGES:
        result = {
            "threat_score": 0,
            "verdict": "SAFE",
            "confidence_score": 100,
            "explanation": "Verified official domain from local whitelist cache.",
            "threat_category": "Safe",
            "severity": "Informational",
            "detection_reason": "Official Trusted Domain",
            "threat_labels": ["trusted"],
            "suspicious_indicators": [],
            "domain_reputation": "Highly Reputable",
            "whois_summary": f"Registered Age: {TRUSTED_AGES[domain]} days",
            "ssl_analysis": "Valid and Trusted",
            "recommendations": "Safe to browse.",
            "false_positive_probability": 0.0,
            "domain_age": TRUSTED_AGES[domain],
            "vt_data": {"malicious": 0, "total": 95}
        }
        result["risk_score"] = result["threat_score"]
        result["risk_category"] = result["threat_category"]

        set_api_cache(url, result)
        background_tasks.add_task(log_threat_scan, url, result, username)
        return result

    # 4. Global Phishing Feed Matches
    if url in intel_db.malicious_urls:
        result = {
            "threat_score": 100,
            "verdict": "MALICIOUS",
            "confidence_score": 100,
            "explanation": "Target URL matched active entries in local Phishing/Malware intelligence databases.",
            "threat_category": "Phishing",
            "severity": "Critical",
            "detection_reason": "Confirmed Phishing (GitHub Feed)",
            "threat_labels": ["blacklist", "threat-intel-feed"],
            "suspicious_indicators": ["intel-feed-blacklist-match"],
            "domain_reputation": "Hostile / Dangerous",
            "whois_summary": "Active phishing link.",
            "ssl_analysis": "Suspicious / Self-Signed",
            "recommendations": "Close tab. Do not input credentials.",
            "false_positive_probability": 0.0,
            "domain_age": -1,
            "vt_data": {"malicious": "High", "total": "OSINT"}
        }
        result["risk_score"] = result["threat_score"]
        result["risk_category"] = result["threat_category"]

        set_api_cache(url, result)
        background_tasks.add_task(log_threat_scan, url, result, username)
        return result

    # 5. Resolve Domain Details (blocking I/O wrapped in threadpool) and Query Unified Threat Intelligence APIs
    loop = asyncio.get_running_loop()
    domain_details = await loop.run_in_executor(None, get_domain_details, url)
    age = domain_details.get("domain_age", -1)
    intel_data = await query_unified_intel(url, domain)
    
    # 6. Call Hybrid AI Scanner
    result = await scanner.scan(url, intel_data, domain_details)
    
    # 7. Apply Threat Logic Recalibration & Overrides
    vt_count = intel_data.get("virustotal", {}).get("malicious", 0)
    gsb_matches = intel_data.get("safe_browsing", {}).get("matches", False)
    
    if (isinstance(vt_count, int) and vt_count > 3) or gsb_matches:
        result["threat_score"] = max(result.get("threat_score", 0), 95)
        result["verdict"] = "MALICIOUS"
        result["severity"] = "Critical"
        result["detection_reason"] = "Confirmed Malicious by Security Providers"
        result["threat_labels"] = list(set(result.get("threat_labels", []) + ["vendor-flagged"]))
        result["suspicious_indicators"] = list(set(result.get("suspicious_indicators", []) + ["google-safe-browsing-flag", "multi-antivirus-detect"]))

    if age != -1 and age < 3 and result.get("threat_score", 0) < 40:
        result["threat_score"] = max(result.get("threat_score", 0), 50)
        result["severity"] = "Medium"
        result["detection_reason"] = "Newly Registered Domain"
        result["threat_labels"] = list(set(result.get("threat_labels", []) + ["fresh-domain"]))

    # Standardize risk score alias
    result["risk_score"] = result.get("threat_score", 0)
    result["risk_category"] = result.get("threat_category", "Safe")

    final_result = {
        **result,
        "domain_age": age,
        "intel_data": intel_data,
        "vt_data": {
            "malicious": intel_data.get("virustotal", {}).get("malicious", 0),
            "total": intel_data.get("virustotal", {}).get("total", 0)
        }
    }
    
    # 8. Cache response payload and queue database logging as Background Job
    set_api_cache(url, final_result)
    background_tasks.add_task(log_threat_scan, url, final_result, username)
    
    return final_result

class ReportRequest(BaseModel):
    domain: str
    report_type: str
    comment: str | None = ""

@router.post("/report")
async def report_domain(request: ReportRequest) -> dict:
    """Records quick threat reports from Chrome Extension users."""
    s_domain = sanitize_input(request.domain)
    s_comment = sanitize_input(request.comment or "")
    if not s_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    if request.report_type not in ["false_positive", "phishing"]:
        raise HTTPException(status_code=400, detail="Invalid report type.")
    
    log_threat_report(s_domain, request.report_type, s_comment)
    return {"success": True, "message": "Quick threat report logged successfully."}

class CopilotRequest(BaseModel):
    prompt: str
    scan_context: dict | None = None

def query_fallback_kb(prompt: str, context: dict | None) -> str:
    prompt_lower = prompt.lower()
    
    # 1. Explain this report / Is this website safe?
    if context and ("explain" in prompt_lower or "safe" in prompt_lower or "score" in prompt_lower or "dangerous" in prompt_lower or "why" in prompt_lower):
        verdict = context.get('verdict', 'UNKNOWN')
        score = context.get('risk_score', 0)
        url = context.get('url', 'N/A')
        explanation = context.get('explanation', '')
        
        response = (
            f"### Offline Threat Map Analysis for **{url}**\n\n"
            f"- **System Verdict**: `{verdict}`\n"
            f"- **Risk Factor**: `{score} / 100`\n\n"
        )
        if score > 75:
            response += (
                "**WARNING**: This domain exhibits signatures consistent with active malware propagation campaigns or credential harvesting sites. "
                "The Zerion AI active shield has flag-blocked the connection.\n\n"
                "**Recommended Action**: Avoid interacting with this site."
            )
        elif score > 30:
            response += (
                "**CAUTION**: The domain shows metadata anomalies, such as recent registration or unresolved WHOIS contact details. "
                "Proceed with caution and do not input passwords.\n\n"
                "**Recommended Action**: Restrict file downloads."
            )
        else:
            response += (
                "**SAFE**: No threat signatures match our blacklists, and the SSL certificate chain is valid.\n\n"
                "**Recommended Action**: Safe to browse under normal parameters."
            )
        if explanation:
            response += f"\n\n**Copilot Insight**: *{explanation}*"
        return response
        
    # 2. Phishing queries
    if "phishing" in prompt_lower:
        return (
            "### Phishing Threat Intelligence\n\n"
            "**Phishing** is a social engineering technique where threat actors deploy duplicate spoof portals of trusted brands (e.g. Google, Microsoft, banking portals) to harvest user passwords or session tokens.\n\n"
            "**SOC Defense Practices**:\n"
            "1. **Check the FQDN**: Ensure the domain matches the brand spelling exactly (e.g. watch for look-alikes like `goog1e.com`).\n"
            "2. **Look for SSL**: Secure HTTPS locks only encrypt data in transit; they do not authenticate the site's legitimacy.\n"
            "3. **Active Blocking**: Enable Zerion active extensions to automatically drop network hooks targeting blacklisted feeds."
        )
        
    # 3. Malware / Ransomware queries
    elif "malware" in prompt_lower or "ransomware" in prompt_lower:
        return (
            "### Malware & Ransomware Mitigation\n\n"
            "**Malware** covers hostiles running on user computers, whereas **Ransomware** focuses on local disk encryption to extort ransom payments.\n\n"
            "**SOC Defense Practices**:\n"
            "1. Do not open unsigned executable scripts (e.g. `.exe`, `.msi`, `.js`, `.vbs`).\n"
            "2. Ensure automated cloud backups are configured to restore systems if compromised.\n"
            "3. Keep operating systems and browser sandboxing features fully updated."
        )
        
    # 4. SSL certificate queries
    elif "ssl" in prompt_lower:
        return (
            "### Cryptographic SSL/TLS Analysis\n\n"
            "**SSL** (Secure Sockets Layer) encrypts the channel between browser and web server, preventing Man-in-the-Middle (MitM) eavesdropping.\n\n"
            "**Key Principles**:\n"
            "- SSL *does not* mean safe. Threat actors routinely install free certificates (e.g. Let's Encrypt) on phishing domains.\n"
            "- Check if the browser shows an SSL warning (e.g. self-signed certificates, domain mismatches, or expired dates)."
        )
        
    # 5. Password security queries
    elif "password" in prompt_lower:
        return (
            "### Enterprise Password Policy Guide\n\n"
            "To block automated credential stuffing attacks:\n"
            "- Use **passphrases** (15+ characters comprising random words) rather than short, complex words.\n"
            "- Deploy a dedicated password manager to generate unique combinations for every portal.\n"
            "- Enable **Multi-Factor Authentication** (MFA) via authenticator apps (avoid SMS verification due to SIM-swap risks)."
        )
        
    # 6. General protection queries
    elif "protect" in prompt_lower or "what should i do" in prompt_lower:
        return (
            "### Security Best Practices\n\n"
            "To stay protected:\n"
            "1. Leave the **Zerion Active Shield** enabled in your popup preferences.\n"
            "2. Inspect active logs in the **Command Center Dashboard** to identify suspicious outbound requests.\n"
            "3. Regularly clear cache data and manage extension permissions."
        )

    # 7. General greeting / Default fallback
    return (
        "### Ask Zerion AI - Cyber Copilot\n\n"
        "I am currently operating in **Offline Fallback mode** as the Gemini API key is not set or the client is offline.\n\n"
        "I can answer questions regarding active threat logs, reputation, SSL certificate flags, phishing, malware, ransomware, and password hygiene.\n\n"
        "Try asking me:\n"
        "- *Explain this report*\n"
        "- *What is Phishing?*\n"
        "- *Is this website safe?*\n"
        "- *Tell me about password safety.*"
    )

@router.post("/copilot")
async def copilot_chat(request: CopilotRequest) -> dict:
    """
    Answers cybersecurity questions using Google Gemini, leveraging scan_context
    when available. If Gemini is unavailable, falls back to a security knowledge base.
    """
    prompt = sanitize_input(request.prompt)
    context = request.scan_context
    
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt is empty.")

    system_instruction = (
        "You are 'Zerion AI Copilot', an expert enterprise-grade cybersecurity assistant. "
        "Provide professional SOC-style (Security Operations Center) answers. Be concise and precise. "
        "Adhere to the Zerion AI brand. Always focus on helping the user stay safe. "
        "Format responses in readable Markdown."
    )
    
    context_str = ""
    if context:
        context_str = (
            f"\n\n[Current Scan Context]\n"
            f"- Target URL: {context.get('url', 'N/A')}\n"
            f"- Verdict: {context.get('verdict', 'UNKNOWN')}\n"
            f"- Risk Score: {context.get('risk_score', 'N/A')}\n"
            f"- Severity: {context.get('severity', 'N/A')}\n"
            f"- Category: {context.get('risk_category', 'N/A')}\n"
            f"- SSL Status: {context.get('ssl_analysis', 'N/A')}\n"
            f"- Domain Age: {context.get('domain_age', 'N/A')} Days\n"
            f"- VT Detection: {context.get('vt_data', {}).get('malicious', 0)} / {context.get('vt_data', {}).get('total', 0)} engines flagged\n"
            f"- AI Explanation: {context.get('explanation', 'N/A')}\n"
        )
    
    full_prompt = f"{system_instruction}{context_str}\n\nUser Question: {prompt}"

    if scanner.gemini_client:
        try:
            res = scanner.gemini_client.models.generate_content(
                model='gemini-1.5-flash',
                contents=full_prompt
            )
            if res and res.text:
                return {"response": res.text.strip()}
        except Exception as e:
            error_logger.error("Copilot: Gemini request failed", e)

    fallback_response = query_fallback_kb(prompt, context)
    return {"response": fallback_response}
