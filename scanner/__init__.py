# scanner/__init__.py
from .service_scanner import scan_services
from .process_scanner import scan_processes
from .utils import get_file_version
from .utils import safe_cvss_score