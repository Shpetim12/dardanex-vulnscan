"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from scanner.header_analyzer import analyze_headers


def test_all_headers_receive_a_grade() -> None:
    headers = {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
    assert analyze_headers(headers, "https://example.test")["grade"] == "A"


def test_missing_headers_are_flagged() -> None:
    result = analyze_headers({}, "http://example.test")
    assert result["grade"] == "F"
    assert all(check["status"] == "missing" for check in result["checks"])
