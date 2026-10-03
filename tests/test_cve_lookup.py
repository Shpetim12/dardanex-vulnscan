"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

import requests

from scanner.cve_lookup import CVELookup, parse_cves, service_keyword


def test_parse_cves_extracts_and_sorts_cvss() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-LOW",
                    "published": "2020-01-01",
                    "descriptions": [{"lang": "en", "value": "low"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-HIGH",
                    "published": "2021-01-01",
                    "descriptions": [{"lang": "en", "value": "high"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]
                    },
                }
            },
        ]
    }
    results = parse_cves(payload)
    assert [item["id"] for item in results] == ["CVE-HIGH", "CVE-LOW"]
    assert results[0]["severity"] == "HIGH"


def test_lookup_uses_mocked_nvd_response_and_cache(tmp_path, monkeypatch) -> None:
    class Response:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-TEST",
                            "published": "2026-01-01",
                            "descriptions": [],
                            "metrics": {},
                        }
                    }
                ]
            }

    calls = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr("scanner.cve_lookup.requests.get", fake_get)
    client = CVELookup(tmp_path / "cache.json", timeout=1)
    assert client.lookup("test product")[0]["id"] == "CVE-TEST"
    assert client.lookup("test product")[0]["id"] == "CVE-TEST"
    assert len(calls) == 1


def test_lookup_handles_empty_and_failed_nvd_responses(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("scanner.cve_lookup.time.sleep", lambda value: None)

    class EmptyResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr("scanner.cve_lookup.requests.get", lambda *args, **kwargs: EmptyResponse())
    client = CVELookup(tmp_path / "empty.json", api_key="test")
    assert client.lookup("empty service") == []

    def fail(*args, **kwargs):
        raise requests.RequestException("offline")

    monkeypatch.setattr("scanner.cve_lookup.requests.get", fail)
    assert CVELookup(tmp_path / "failed.json", api_key="test").lookup("failed service") == []
    assert service_keyword({"product": "Apache", "version": "2.4"}) == "Apache 2.4"
    assert service_keyword({"product": "Apache"}) is None
