import httpx
import asyncio
from backend.utils.logger import app_logger, error_logger

class ThreatIntel:
    """Manages active threat intelligence feeds pulled from open security resources."""
    
    def __init__(self) -> None:
        self.malicious_urls: set[str] = set()
        self.loaded: bool = False

    async def update_feeds(self) -> None:
        """Asynchronously fetches active phishing links and malware threats from open sources concurrently."""
        app_logger.info("Updating Threat Intelligence feeds from GitHub, URLHaus, and OpenPhish...")
        sources = [
            "https://urlhaus.abuse.ch/downloads/text_online/",
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
            "https://openphish.com/feed.txt"
        ]
        
        async with httpx.AsyncClient() as client:
            async def fetch_source(source: str) -> set[str]:
                local_set = set()
                try:
                    r = await client.get(source, timeout=15.0)
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            line_str = line.strip()
                            if not line_str.startswith("#") and line_str:
                                local_set.add(line_str)
                except Exception as e:
                    error_logger.error(f"Feed sync error from source: {source}", e)
                return local_set

            results = await asyncio.gather(*(fetch_source(source) for source in sources))
            for res in results:
                self.malicious_urls.update(res)
            
            self.loaded = True
        app_logger.info(f"Threat Intelligence updated successfully: {len(self.malicious_urls)} active entries loaded.")

intel_db = ThreatIntel()
