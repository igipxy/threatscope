from fastapi.testclient import TestClient

from app.main import app, settings
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
