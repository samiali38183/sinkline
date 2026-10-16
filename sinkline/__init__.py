"""sinkline — interprocedural taint analysis for Python web apps, mapped to OWASP Top 10.

Public surface:
    from sinkline import scan_path, scan_source
    result = scan_path("path/to/app")
    for f in result.findings: print(f.render())
"""

from .engine import scan_path, scan_source, ScanResult
from .finding import Finding, FlowStep

__version__ = "0.3.0"
__all__ = ["scan_path", "scan_source", "ScanResult", "Finding", "FlowStep", "__version__"]
