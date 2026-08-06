import logging
import json
import sys
from datetime import datetime

# Configure standard root log layout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

class StructuredLogger:
    """Helper to generate structured JSON-like console logs for telemetry analysis."""
    
    def __init__(self, category: str) -> None:
        self.logger = logging.getLogger(category)

    def info(self, msg: str, **kwargs) -> None:
        log_data = {"timestamp": datetime.now().isoformat(), "message": msg, **kwargs}
        self.logger.info(json.dumps(log_data))

    def warn(self, msg: str, **kwargs) -> None:
        log_data = {"timestamp": datetime.now().isoformat(), "message": msg, **kwargs}
        self.logger.warning(json.dumps(log_data))

    def error(self, msg: str, exc: Exception | None = None, **kwargs) -> None:
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "message": msg,
            "error_type": type(exc).__name__ if exc else None,
            "error_details": str(exc) if exc else None,
            **kwargs
        }
        self.logger.error(json.dumps(log_data))

# Structured Loggers divided by system scope
request_logger = StructuredLogger("ZerionRequest")
error_logger = StructuredLogger("ZerionError")
threat_logger = StructuredLogger("ZerionThreat")
app_logger = StructuredLogger("ZerionApp")
