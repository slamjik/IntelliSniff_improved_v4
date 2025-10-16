import os
# Configuration for IntelliSniff
MAX_ROWS = int(os.getenv("INTELLISNIFF_MAX_ROWS", "1000000"))
FLOW_TIMEOUT = float(os.getenv("INTELLISNIFF_FLOW_TIMEOUT", "30.0"))
USE_PYSHARK = os.getenv("INTELLISNIFF_USE_PYSHARK", "0") in ("1","true","True")
