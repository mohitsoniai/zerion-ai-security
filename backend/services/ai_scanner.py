import json
import collections
from config.settings import settings
from utils.logger import error_logger, app_logger, threat_logger
from google import genai
from groq import Groq

class HybridScanner:
    """
    Hybrid threat scanner combining Groq Llama and Gemini Multimodal AI capabilities,
    equipped with zero-latency in-memory scan caching.
    """
    
    def __init__(self) -> None:
        self.groq = Groq(api_key=settings.groq_api_key) if settings.groq_api_key else None
        if settings.gemini_api_key: 
            self.gemini_client = genai.Client(api_key=settings.gemini_api_key)
        else:
            self.gemini_client = None
            
        # In-memory size-bounded LRU Cache for scan results
        self.cache_limit = 500
        self.cache: collections.OrderedDict[str, dict] = collections.OrderedDict()

    async def scan(self, url: str, intel_data: dict, domain_details: dict | int) -> dict:
        """
        Analyzes the target URL using Groq Llama or Google Gemini, returning a structured JSON response.
        Optimized via in-memory caching to avoid redundant API transactions.
        """
        if url in self.cache:
            app_logger.info(f"Cache hit: scan results retrieved for URL: {url}")
            self.cache.move_to_end(url)
            return self.cache[url]

        # Extract stats from unified threat intelligence engine
        vt_score = intel_data.get("virustotal", {}).get("malicious", 0)
        gsb_matches = intel_data.get("safe_browsing", {}).get("matches", False)
        urlscan_score = intel_data.get("urlscan", {}).get("score", 0)
        abuse_score = intel_data.get("abuseipdb", {}).get("abuse_score", 0)
        resolved_ip = intel_data.get("resolved_ip", "0.0.0.0")
        openphish_match = intel_data.get("openphish", {}).get("matches", False)

        # Parse domain details
        if isinstance(domain_details, int):
            age = domain_details
            details_str = f"- Domain Registration Age: {age} days\n"
        else:
            age = domain_details.get("domain_age", -1)
            details_str = (
                f"- Domain Registration Age: {age} days\n"
                f"- Registrar: {domain_details.get('registrar', 'Unknown')}\n"
                f"- Creation Date: {domain_details.get('creation_date', 'Unknown')}\n"
                f"- SSL Certificate Issuer: {domain_details.get('ssl_issuer', 'Unknown')}\n"
                f"- SSL Expiry: {domain_details.get('ssl_expiry', 'Unknown')}\n"
                f"- SSL Valid: {domain_details.get('ssl_valid', False)}\n"
            )

        system_prompt = (
            "You are Zerion Security AI v5.0. You analyze URLs for phishing, malware, and social engineering threats.\n"
            "BE OBJECTIVE, NOT PARANOID. If VirusTotal is 0 and the domain age is > 30 days old, default to SAFE.\n"
            "You MUST analyze and return ONLY a valid JSON object matching exactly this schema:\n"
            "{\n"
            "  \"threat_score\": int (0-100),\n"
            "  \"verdict\": \"SAFE\" or \"MALICIOUS\",\n"
            "  \"confidence_score\": int (0-100),\n"
            "  \"explanation\": \"Detailed text explaining the reasoning for your verdict.\",\n"
            "  \"threat_category\": \"Phishing\" or \"Malware\" or \"XSS\" or \"Social Engineering\" or \"Safe\",\n"
            "  \"severity\": \"Informational\" or \"Low\" or \"Medium\" or \"High\" or \"Critical\",\n"
            "  \"detection_reason\": \"Short description of the primary trigger\",\n"
            "  \"threat_labels\": [\"tag1\", \"tag2\"],\n"
            "  \"suspicious_indicators\": [\"indicator1\", \"indicator2\"],\n"
            "  \"domain_reputation\": \"Analysis of domain trustworthiness\",\n"
            "  \"whois_summary\": \"Summary of domain WHOIS age and registrar\",\n"
            "  \"ssl_analysis\": \"Status of SSL/TLS certificate validity\",\n"
            "  \"recommendations\": \"Clear mitigation advice for the end-user\",\n"
            "  \"false_positive_probability\": float (0.0 to 100.0)\n"
            "}"
        )
        
        user_prompt = (
            f"Analyze URL: '{url}'.\n"
            f"Context Details:\n"
            f"{details_str}"
            f"- Resolved IP: {resolved_ip}\n"
            f"- VirusTotal Detections Count: {vt_score}\n"
            f"- Google Safe Browsing Flagged: {gsb_matches}\n"
            f"- URLScan Malicious Score: {urlscan_score}\n"
            f"- AbuseIPDB Confidence Score: {abuse_score}\n"
            f"- OpenPhish/Local Feed Match: {openphish_match}\n"
        )

        result = None

        # A. Try Groq Llama
        if self.groq:
            try:
                res = self.groq.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                if res.choices[0].message.content:
                    result = json.loads(res.choices[0].message.content)
            except Exception as e:
                error_logger.error("Groq AI Scan exception raised", e)

        # B. Fallback to Google Gemini
        if not result and self.gemini_client:
            try:
                res = self.gemini_client.models.generate_content(
                    model='gemini-1.5-flash',
                    contents=f"{system_prompt}\n\n{user_prompt}"
                )
                if res.text:
                    clean_json = res.text.replace("```json", "").replace("```", "").strip()
                    result = json.loads(clean_json)
            except Exception as e:
                error_logger.error("Gemini AI Scan exception raised", e)

        # C. Default Safe Fallback
        if not result:
            result = {
                "threat_score": 0,
                "verdict": "SAFE",
                "confidence_score": 100,
                "explanation": "Default evaluation fallback. Unable to query AI scanner.",
                "threat_category": "Safe",
                "severity": "Informational",
                "detection_reason": "Default safe policy fallback",
                "threat_labels": [],
                "suspicious_indicators": [],
                "domain_reputation": "Clean / Whitelisted",
                "whois_summary": f"Age: {age} days",
                "ssl_analysis": "Valid",
                "recommendations": "No action required.",
                "false_positive_probability": 0.0
            }
            
        # Standardize naming alias for risk_score (compatibility with dashboard and extension)
        result["risk_score"] = result.get("threat_score", 0)
        result["risk_category"] = result.get("threat_category", "Safe")

        # Log threat if malicious
        if result.get("verdict") == "MALICIOUS" or result.get("threat_score", 0) > 75:
            threat_logger.info(
                f"Malicious threat detected: {url}", 
                risk_score=result.get("threat_score"), 
                severity=result.get("severity"),
                category=result.get("threat_category")
            )

        # Store in LRU Cache
        self.cache[url] = result
        if len(self.cache) > self.cache_limit:
            self.cache.popitem(last=False)

        return result

scanner = HybridScanner()
