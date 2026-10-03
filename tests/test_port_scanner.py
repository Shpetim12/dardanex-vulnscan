"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.port_scanner import NmapUnavailableError, find_nmap_binary, scan_ports


def test_find_nmap_binary_prefers_path(monkeypatch) -> None:
    monkeypatch.setattr("scanner.port_scanner.shutil.which", lambda name: "/usr/bin/nmap")
    assert find_nmap_binary() == "/usr/bin/nmap"


def test_find_nmap_binary_reports_install_instructions(monkeypatch) -> None:
    monkeypatch.setattr("scanner.port_scanner.shutil.which", lambda name: None)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    with pytest.raises(NmapUnavailableError, match="Windows"):
        find_nmap_binary()


def test_find_nmap_binary_uses_standard_windows_path(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "nmap.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr("scanner.port_scanner.shutil.which", lambda name: None)
    monkeypatch.setattr("scanner.port_scanner.WINDOWS_NMAP_PATHS", (binary,))
    assert find_nmap_binary() == str(binary)


def test_scan_ports_normalizes_mocked_nmap_results(monkeypatch) -> None:
    class FakeHost(dict):
        def all_protocols(self):
            return ["tcp"]

    class FakeScanner:
        def __init__(self, nmap_search_path):
            self.nmap_search_path = nmap_search_path
            self.host = FakeHost(
                tcp={
                    22: {
                        "state": "open",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "9.0",
                        "extrainfo": "",
                    },
                    23: {"state": "closed"},
                }
            )

        def scan(self, **kwargs):
            self.scan_arguments = kwargs

        def all_hosts(self):
            return ["192.0.2.10"]

        def __getitem__(self, host):
            return self.host

    fake_nmap = SimpleNamespace(PortScanner=FakeScanner, PortScannerError=RuntimeError)
    monkeypatch.setitem(sys.modules, "nmap", fake_nmap)

    ports = scan_ports("192.0.2.10", scan_type="quick", nmap_binary="/mock/nmap")

    assert ports == [
        {
            "host": "192.0.2.10",
            "protocol": "tcp",
            "port": 22,
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.0",
            "extrainfo": "",
        }
    ]
