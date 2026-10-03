"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

import socket

import pytest

from scanner.dns_resolver import resolve_target, validate_target


def test_validate_target_normalizes_hostnames_and_ips() -> None:
    assert validate_target(" Example.COM. ") == "example.com"
    assert validate_target("2001:0db8::1") == "2001:db8::1"


@pytest.mark.parametrize("target", ["", "bad host", "example.com;whoami"])
def test_validate_target_rejects_unsafe_values(target: str) -> None:
    with pytest.raises(ValueError):
        validate_target(target)


def test_resolve_target_collects_addresses_and_reverse_dns(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.dns_resolver.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
        ],
    )
    monkeypatch.setattr(
        "scanner.dns_resolver.socket.gethostbyaddr",
        lambda address: (f"host-{address}", [], [address]),
    )

    result = resolve_target("example.com")

    assert result["ipv4"] == ["192.0.2.10"]
    assert result["ipv6"] == ["2001:db8::10"]
    assert result["reverse"]["192.0.2.10"] == "host-192.0.2.10"


def test_resolve_target_handles_lookup_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "scanner.dns_resolver.socket.getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror("not found")),
    )

    result = resolve_target("example.com")

    assert result["ipv4"] == []
    assert "DNS resolution failed" in result["errors"][0]


def test_resolve_target_handles_timeout(monkeypatch) -> None:
    class TimedOutFuture:
        def result(self, timeout):
            raise TimeoutError

        def cancel(self):
            return True

    class Executor:
        def __init__(self, max_workers):
            self.max_workers = max_workers

        def submit(self, *args):
            return TimedOutFuture()

        def shutdown(self, **kwargs):
            return None

    monkeypatch.setattr("scanner.dns_resolver.ThreadPoolExecutor", Executor)

    result = resolve_target("example.com", timeout=1)

    assert result["errors"] == ["DNS resolution timed out after 1 seconds."]
