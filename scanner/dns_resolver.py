"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z"
)


def validate_target(target: str) -> str:
    """Return a normalized IP address or hostname, or raise ``ValueError``."""
    value = target.strip().rstrip(".")
    if not value or len(value) > 253 or any(char.isspace() for char in value):
        raise ValueError("Target must be a non-empty hostname or IP address.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(value):
        raise ValueError("Target contains invalid hostname characters.")
    return value.lower()


def resolve_target(target: str, timeout: float = 10.0) -> dict[str, Any]:
    """Resolve A/AAAA records and attempt PTR lookups without failing the scan."""
    target = validate_target(target)
    result: dict[str, Any] = {"target": target, "ipv4": [], "ipv6": [], "reverse": {}, "errors": []}
    if timeout <= 0:
        raise ValueError("DNS timeout must be greater than zero.")
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(socket.getaddrinfo, target, None, 0, socket.SOCK_STREAM)
    try:
        records = future.result(timeout=timeout)
    except FutureTimeoutError:
        future.cancel()
        result["errors"].append(f"DNS resolution timed out after {timeout:g} seconds.")
        return result
    except socket.gaierror as exc:
        result["errors"].append(f"DNS resolution failed: {exc}")
        return result
    except OSError as exc:
        result["errors"].append(f"DNS lookup error: {exc}")
        return result
    finally:
        # Resolver threads are allowed to finish in the background after a timeout.
        executor.shutdown(wait=False, cancel_futures=True)

    addresses = {(family, address[0]) for family, _, _, _, address in records}
    for family, address in sorted(addresses, key=lambda item: (item[0], item[1])):
        key = "ipv4" if family == socket.AF_INET else "ipv6"
        result[key].append(address)
        try:
            hostname, _, _ = socket.gethostbyaddr(address)
            result["reverse"][address] = hostname
        except (socket.herror, socket.gaierror, OSError):
            continue
    return result
