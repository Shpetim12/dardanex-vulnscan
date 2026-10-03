"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_cves(payload: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    """Extract consistently shaped, score-sorted CVEs from an NVD API payload."""
    findings: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        metric_candidates = [values[0] for key, values in metrics.items() if key.startswith("cvssMetric") and values]
        metric = max(metric_candidates, key=lambda value: value.get("cvssData", {}).get("baseScore", -1), default={})
        cvss = metric.get("cvssData", {})
        description = next((entry.get("value", "") for entry in cve.get("descriptions", []) if entry.get("lang") == "en"), "")
        findings.append({
            "id": cve.get("id", "unknown"), "description": description,
            "score": cvss.get("baseScore"), "severity": cvss.get("baseSeverity", "UNKNOWN").upper(),
            "published": cve.get("published", ""),
        })
    return sorted(findings, key=lambda c: c["score"] if isinstance(c["score"], (int, float)) else -1, reverse=True)[:limit]


class CVELookup:
    """NVD client that caches keyword results and retries transient failures."""

    def __init__(self, cache_path: Path, timeout: float = 15.0, api_key: str | None = None) -> None:
        self.cache_path, self.timeout = cache_path, timeout
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache = self._load_cache()
        self._last_request = 0.0

    def _load_cache(self) -> dict[str, Any]:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")

    def lookup(self, keyword: str, limit: int = 5) -> list[dict[str, Any]]:
        """Return cached or live results for a product/version keyword."""
        key = keyword.lower().strip()
        if key in self.cache:
            return self.cache[key][:limit]
        # NVD permits a faster cadence with a key; use conservative spacing in both cases.
        min_interval = 0.7 if self.api_key else 6.1
        time.sleep(max(0.0, min_interval - (time.monotonic() - self._last_request)))
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(3):
            try:
                response = requests.get(NVD_URL, params={"keywordSearch": key, "resultsPerPage": min(limit, 20)}, headers=headers, timeout=self.timeout)
                self._last_request = time.monotonic()
                if response.status_code == 429 or response.status_code >= 500:
                    raise requests.HTTPError(f"NVD returned HTTP {response.status_code}", response=response)
                response.raise_for_status()
                results = parse_cves(response.json(), limit)
                self.cache[key] = results
                self._save_cache()
                return results
            except (requests.RequestException, ValueError) as exc:
                if attempt == 2:
                    LOGGER.warning("CVE lookup failed for %s: %s", key, exc)
                    return []
                time.sleep(2 ** attempt)
        return []


def service_keyword(service: dict[str, Any]) -> str | None:
    """Build an NVD keyword only when nmap found a meaningful product/version."""
    product, version = service.get("product", "").strip(), service.get("version", "").strip()
    if product and version:
        return f"{product} {version}"
    return None
