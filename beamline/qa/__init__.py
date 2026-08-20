"""Quality-assurance suites: NIST SP 800-22 and SP 800-90B.

Requires NumPy. Install with the `qa` extra:  pip install -e ".[qa]"
"""

from . import report, sp80022, sp80090b

__all__ = ["sp80022", "sp80090b", "report"]
