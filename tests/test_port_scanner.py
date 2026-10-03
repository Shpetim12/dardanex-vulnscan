"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from pathlib import Path

import pytest

from scanner.port_scanner import NmapUnavailableError, find_nmap_binary


def test_find_nmap_binary_prefers_path(monkeypatch) -> None:
    monkeypatch.setattr("scanner.port_scanner.shutil.which", lambda name: "/usr/bin/nmap")
    assert find_nmap_binary() == "/usr/bin/nmap"


def test_find_nmap_binary_reports_install_instructions(monkeypatch) -> None:
    monkeypatch.setattr("scanner.port_scanner.shutil.which", lambda name: None)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    with pytest.raises(NmapUnavailableError, match="Windows"):
        find_nmap_binary()
