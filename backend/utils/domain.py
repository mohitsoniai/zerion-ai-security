import ssl
import socket
import whois
from datetime import datetime
from utils.logger import error_logger

# TRUSTED DOMAINS (Whitelist Ages to avoid network calls)
TRUSTED_AGES = {
    "google.com": 9500, "youtube.com": 6900, "wikipedia.org": 8700, 
    "github.com": 5800, "microsoft.com": 11000, "huggingface.co": 1500,
    "stackoverflow.com": 7000, "amazon.com": 10500, "apple.com": 13000,
    "netflix.com": 9000, "linkedin.com": 7500, "whatsapp.com": 5000,
    "openai.com": 3000, "facebook.com": 7600, "instagram.com": 4500,
    "twitter.com": 6500, "x.com": 10000, "twitch.tv": 4000,
    "gmail.com": 9500, "outlook.com": 8000, "yahoo.com": 10000,
    "paruluniversity.ac.in": 5000
}

def get_domain_details(url: str) -> dict:
    """
    Retrieves domain security metrics including WHOIS age, registrar, SSL issuer, SSL expiry, and validity.
    
    Args:
        url: The full target URL to analyze.
        
    Returns:
        A dictionary containing registrar, domain age (in days), creation date, ssl_issuer, ssl_expiry, and ssl_valid.
    """
    details = {
        "domain_age": -1,
        "registrar": "Unknown",
        "ssl_issuer": "Unknown",
        "ssl_expiry": "Unknown",
        "ssl_valid": False,
        "creation_date": "Unknown"
    }
    
    try:
        domain = url.split("//")[-1].split("/")[0].replace("www.", "").split(":")[0]
    except Exception:
        return details
        
    if domain in TRUSTED_AGES:
        details["domain_age"] = TRUSTED_AGES[domain]
        details["registrar"] = "Established Registrar"
        details["ssl_issuer"] = "Trusted Authority"
        details["ssl_valid"] = True
        details["creation_date"] = "Whitelisted/Trusted"
        return details

    # 1. Try WHOIS lookup
    try:
        socket.setdefaulttimeout(2.0)
        w = whois.whois(domain)
        if w:
            details["registrar"] = w.registrar or "Unknown"
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if isinstance(creation_date, str):
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            creation_date = datetime.strptime(creation_date, fmt)
                            break
                        except:
                            pass
                if isinstance(creation_date, datetime):
                    details["domain_age"] = (datetime.now() - creation_date).days
                    details["creation_date"] = creation_date.strftime("%Y-%m-%d")
    except Exception:
        pass

    # 2. Try SSL Certificate inspection
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    details["ssl_valid"] = True
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    details["ssl_issuer"] = issuer.get('organizationName') or issuer.get('commonName') or "Unknown"
                    expiry_str = cert.get('notAfter')
                    if expiry_str:
                        details["ssl_expiry"] = expiry_str
                    
                    # If WHOIS failed to resolve domain age, estimate domain age from certificate issuance (notBefore)
                    if details["domain_age"] == -1:
                        start_date_str = cert.get('notBefore')
                        if start_date_str:
                            start_date = datetime.strptime(start_date_str, "%b %d %H:%M:%S %Y %Z")
                            details["domain_age"] = (datetime.now() - start_date).days
    except Exception:
        pass

    return details

def get_domain_age(url: str) -> int:
    """
    Wrapper for backward compatibility to retrieve the domain age in days.
    """
    details = get_domain_details(url)
    return details.get("domain_age", -1)
