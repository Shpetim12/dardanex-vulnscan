"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from .dns_resolver import validate_target

LOGGER = logging.getLogger(__name__)
SCAN_ARGUMENTS = {
    "quick": "-sV --top-ports 100",
    "default": "-sV --top-ports 1000",
    "full": "-sV -p 1-65535",
}


class NmapUnavailableError(RuntimeError):
    """Raised when python-nmap or its system nmap executable is unavailable."""


WINDOWS_NMAP_PATHS = (
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
)
INSTALL_INSTRUCTIONS = (
    "Nmap was not found. Install it, then retry: Windows: https://nmap.org/download; "
    "Linux (Debian/Ubuntu): sudo apt install nmap; macOS: brew install nmap."
)


def find_nmap_binary() -> str:
    """Find Nmap on PATH or in its usual Windows installation locations."""
    on_path = shutil.which("nmap")
    if on_path:
        return on_path
    for candidate in WINDOWS_NMAP_PATHS:
        if candidate.is_file():
            return str(candidate)
    raise NmapUnavailableError(INSTALL_INSTRUCTIONS)


def scan_ports(
    target: str,
    scan_type: str = "default",
    timeout: float = 10.0,
    nmap_binary: str | None = None,
) -> list[dict[str, Any]]:
    """Run a TCP service/version scan and return normalized open-port records."""
    if scan_type not in SCAN_ARGUMENTS:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    target = validate_target(target)
    try:
        import nmap  # type: ignore[import-not-found]
    except ImportError as exc:
        raise NmapUnavailableError(
            "python-nmap is not installed. Run: pip install -r requirements.txt"
        ) from exc
    nmap_binary = nmap_binary or find_nmap_binary()
    try:
        scanner = nmap.PortScanner(nmap_search_path=(nmap_binary,))
    except nmap.PortScannerError as exc:
        raise NmapUnavailableError(
            f"Nmap could not be started from {nmap_binary}. {INSTALL_INSTRUCTIONS}"
        ) from exc
    try:
        scanner.scan(hosts=target, arguments=SCAN_ARGUMENTS[scan_type], timeout=int(timeout))
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to start nmap: {exc}") from exc

    ports: list[dict[str, Any]] = []
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            for port, data in scanner[host][protocol].items():
                if data.get("state") != "open":
                    continue
                ports.append(
                    {
                        "host": host,
                        "protocol": protocol,
                        "port": int(port),
                        "service": data.get("name", "unknown"),
                        "product": data.get("product", ""),
                        "version": data.get("version", ""),
                        "extrainfo": data.get("extrainfo", ""),
                    }
                )
    return sorted(ports, key=lambda item: (item["host"], item["protocol"], item["port"]))
