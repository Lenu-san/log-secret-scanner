"""log-secret-scanner — détection de secrets en clair dans des journaux et fichiers texte."""

from .patterns import PATTERNS, SEVERITY_ORDER  # noqa: F401
from .scanner import scan, scan_file, scan_line, exit_code  # noqa: F401
