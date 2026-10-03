"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

__version__ = "1.0.0"
__author__ = "Shpetim"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2026 Shpetim / Dardanex"

from .dns_resolver import resolve_target, validate_target

__all__ = [
    "__author__",
    "__copyright__",
    "__license__",
    "__version__",
    "resolve_target",
    "validate_target",
]
