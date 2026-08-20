from fastapi.testclient import TestClient

from app.main import app, settings


def test_scan_is_saved_and_returned_in_history(tmp_path):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = ""

    with TestClient(app) as client:
        created = client.post("/api/scans", json={"target": "example.com"})

        assert created.status_code == 201
        assert created.json()["verdict"] == "low_risk"
        assert created.json()["analysis_status"] == "completed"

        history = client.get("/api/scans")
        assert history.status_code == 200
        assert len(history.json()) == 1
        assert history.json()[0]["target"] == "example.com"


def test_virus_total_is_not_used_without_explicit_consent(tmp_path):
    settings.database_path = str(tmp_path / "test.db")
    settings.virustotal_api_key = "test-key"

    with TestClient(app) as client:
        created = client.post("/api/scans", json={"target": "example.com"})

    assert created.status_code == 201
    assert created.json()["provider"] == "ThreatScope structural and DNS analysis"
    assert any(item["label"] == "VirusTotal sharing disabled" for item in created.json()["findings"])


def test_rejects_unsupported_url_scheme(tmp_path):
    settings.database_path = str(tmp_path / "test.db")

    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "ftp://example.com"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Only HTTP and HTTPS URLs can be scanned."
