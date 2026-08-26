import httpx
from fastapi.testclient import TestClient

from app import main as main_module
from app.main import app, settings
from app.models import Finding
from app.storage import initialize_database, reserve_provider_request


def test_scan_is_cached_after_first_result(tmp_path):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = ""

    with TestClient(app) as client:
        first = client.post("/api/scans", json={"target": "example.com"})
        second = client.post("/api/scans", json={"target": "example.com"})

    assert first.status_code == 201
    assert first.json()["verdict"] == "low_risk"
    assert second.status_code == 201
    assert second.json()["cached"] is True
    assert second.json()["id"] == first.json()["id"]


def test_virus_total_is_not_used_without_explicit_consent(tmp_path):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = "test-key"

    with TestClient(app) as client:
        created = client.post("/api/scans", json={"target": "example.com"})

    assert created.status_code == 201
    assert created.json()["provider"] == "ThreatScope local analysis"
    assert any(item["label"] == "VirusTotal lookup disabled" for item in created.json()["findings"])


def test_provider_mode_does_not_reuse_local_cache(tmp_path, monkeypatch):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = ""
    provider_calls = 0

    async def fake_virustotal_report(target, target_type):
        nonlocal provider_calls
        provider_calls += 1
        return 60, [
            Finding(
                label="VirusTotal engine analysis",
                severity="high",
                detail="Test provider result.",
            )
        ]

    monkeypatch.setattr(main_module, "virustotal_report", fake_virustotal_report)

    with TestClient(app) as client:
        local_result = client.post("/api/scans", json={"target": "8.8.8.8"})
        settings.virustotal_api_key = "test-key"
        enriched_result = client.post(
            "/api/scans",
            json={"target": "8.8.8.8", "share_with_virustotal": True},
        )
        cached_enriched_result = client.post(
            "/api/scans",
            json={"target": "8.8.8.8", "share_with_virustotal": True},
        )

    assert local_result.status_code == 201
    assert enriched_result.status_code == 201
    assert enriched_result.json()["cached"] is False
    assert enriched_result.json()["provider"] == "ThreatScope + VirusTotal report"
    assert cached_enriched_result.json()["cached"] is True
    assert cached_enriched_result.json()["id"] == enriched_result.json()["id"]
    assert provider_calls == 1


def test_rejects_direct_non_public_ip(tmp_path):
    settings.database_path = str(tmp_path / "test.db")

    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "127.0.0.1"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Local, private, and reserved IP addresses cannot be scanned."


def test_provider_timeout_keeps_local_result(tmp_path, monkeypatch):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = "test-key"

    class FailingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, *args, **kwargs):
            raise httpx.ReadTimeout("provider timed out")

    monkeypatch.setattr(main_module.httpx, "AsyncClient", lambda *args, **kwargs: FailingClient())

    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            json={"target": "8.8.4.4", "share_with_virustotal": True},
        )

    assert response.status_code == 201
    assert response.json()["provider"] == "ThreatScope + VirusTotal report"
    assert any(item["label"] == "VirusTotal unavailable" for item in response.json()["findings"])


def test_provider_budget_stops_excess_requests(tmp_path):
    database_path = str(tmp_path / "test.db")
    initialize_database(database_path)

    assert reserve_provider_request(database_path, "virustotal", 1, 400)[0] is True
    allowed, reason = reserve_provider_request(database_path, "virustotal", 1, 400)

    assert allowed is False
    assert reason == "per-minute budget reached"


def test_rejects_unsupported_url_scheme(tmp_path):
    settings.database_path = str(tmp_path / "test.db")

    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "ftp://example.com"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Only HTTP and HTTPS URLs can be scanned."
