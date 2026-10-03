"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from __future__ import annotations

from typing import Any

import requests

REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS tells browsers to use HTTPS.",
        "Enable HSTS on HTTPS responses with a long max-age.",
    ),
    "Content-Security-Policy": (
        "CSP reduces script-injection impact.",
        "Deploy a restrictive Content-Security-Policy.",
    ),
    "X-Frame-Options": (
        "Frame embedding can enable clickjacking.",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    ),
    "X-Content-Type-Options": (
        "MIME sniffing can lead to content-type confusion.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "Referrer-Policy": (
        "Referrers may expose sensitive URLs.",
        "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "Browser features may be unnecessarily available.",
        "Set a Permissions-Policy appropriate for the application.",
    ),
}


def analyze_headers(headers: dict[str, str], url: str) -> dict[str, Any]:
    """Assess headers from a response and assign an A-F presence/quality grade."""
    normalized = {key.lower(): value for key, value in headers.items()}
    checks: list[dict[str, str]] = []
    present = 0
    for name, (reason, recommendation) in REQUIRED_HEADERS.items():
        value = normalized.get(name.lower())
        status = "present"
        if not value:
            status = "missing"
        elif name == "X-Content-Type-Options" and value.lower().strip() != "nosniff":
            status = "weak"
        elif name == "X-Frame-Options" and value.upper().strip() not in {"DENY", "SAMEORIGIN"}:
            status = "weak"
        elif (
            name == "Strict-Transport-Security"
            and url.lower().startswith("https")
            and "max-age=" not in value.lower()
        ):
            status = "weak"
        if status == "present":
            present += 1
        checks.append(
            {
                "header": name,
                "status": status,
                "value": value or "",
                "explanation": reason,
                "recommendation": recommendation,
            }
        )
    score = present / len(REQUIRED_HEADERS)
    grade = (
        "A"
        if score == 1
        else "B"
        if score >= 0.8
        else "C"
        if score >= 0.6
        else "D"
        if score >= 0.4
        else "F"
    )
    disclosure = {
        name: normalized.get(name.lower(), "")
        for name in ("Server", "X-Powered-By")
        if normalized.get(name.lower())
    }
    return {"url": url, "grade": grade, "checks": checks, "disclosure_headers": disclosure}


def fetch_and_analyze(url: str, timeout: float) -> dict[str, Any]:
    """Fetch one URL safely and return analysis or a user-facing error."""
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "vulnscan/1.0 (authorized security testing)"},
        )
        analysis = analyze_headers(dict(response.headers), response.url)
        analysis["status_code"] = response.status_code
        return analysis
    except requests.RequestException as exc:
        return {"url": url, "error": f"HTTP request failed: {exc}"}
