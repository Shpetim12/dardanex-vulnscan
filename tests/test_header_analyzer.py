"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

import requests

from scanner.header_analyzer import analyze_headers, fetch_and_analyze


def test_all_headers_receive_a_grade() -> None:
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    assert analyze_headers(headers, "https://example.test")["grade"] == "A"


def test_missing_headers_are_flagged() -> None:
    result = analyze_headers({}, "http://example.test")
    assert result["grade"] == "F"
    assert all(check["status"] == "missing" for check in result["checks"])


def test_fetch_and_analyze_uses_mocked_response(monkeypatch) -> None:
    class Response:
        headers = {"X-Frame-Options": "DENY"}
        url = "https://example.test/"
        status_code = 200

    monkeypatch.setattr("scanner.header_analyzer.requests.get", lambda *args, **kwargs: Response())

    result = fetch_and_analyze("https://example.test", timeout=1)

    assert result["status_code"] == 200
    assert result["grade"] == "F"


def test_fetch_and_analyze_handles_request_error(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise requests.RequestException("offline")

    monkeypatch.setattr("scanner.header_analyzer.requests.get", fail)

    assert "HTTP request failed" in fetch_and_analyze("https://example.test", timeout=1)["error"]
