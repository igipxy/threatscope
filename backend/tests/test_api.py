import httpx
import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.main import ProviderOutcome, app, settings
from app.models import Finding
from app.storage import initialize_database, reserve_provider_request


@pytest.fixture(autouse=True)
def isolate_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "database_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "virustotal_api_key", "")
    monkeypatch.setattr(settings, "cache_ttl_seconds", 86400)
    monkeypatch.setattr(settings, "vt_requests_per_minute", 3)
    monkeypatch.setattr(settings, "vt_requests_per_day", 400)
    monkeypatch.setattr(settings, "access_token", "")
    monkeypatch.setattr(settings, "scan_requests_per_minute", 20)
    monkeypatch.setattr(settings, "max_stored_scans", 500)
    monkeypatch.setattr(main_module, "_loopback_request", lambda request: True)
    main_module._scan_requests.clear()


def test_scan_is_cached_after_first_result():
    with TestClient(app) as client:
        first = client.post("/api/scans", json={"target": "example.com"})
        second = client.post("/api/scans", json={"target": "example.com"})

    assert first.status_code == 201
    assert first.json()["verdict"] == "low_risk"
    assert second.status_code == 201
    assert second.json()["cached"] is True
    assert second.json()["id"] == first.json()["id"]


def test_virus_total_is_not_used_without_explicit_consent(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")

    with TestClient(app) as client:
        created = client.post("/api/scans", json={"target": "example.com"})

    assert created.status_code == 201
    assert created.json()["provider"] == "ThreatScope local analysis"
    assert any(item["label"] == "VirusTotal lookup disabled" for item in created.json()["findings"])


def test_provider_mode_does_not_reuse_local_cache(monkeypatch):
    provider_calls = 0

    async def fake_virustotal_report(target, target_type):
        nonlocal provider_calls
        provider_calls += 1
        return ProviderOutcome(
            status="success",
            score=60,
            findings=[
                Finding(
                    label="VirusTotal engine analysis",
                    severity="high",
                    detail="Test provider result.",
                )
            ],
        )

    monkeypatch.setattr(main_module, "virustotal_report", fake_virustotal_report)

    with TestClient(app) as client:
        local_result = client.post("/api/scans", json={"target": "8.8.8.8"})
        monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
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


def test_rejects_direct_non_public_ip():
    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "127.0.0.1"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Local, private, and reserved IP addresses cannot be scanned."


def test_provider_timeout_is_not_cached_as_a_report(monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
    provider_calls = 0

    class FailingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def get(self, *args, **kwargs):
            nonlocal provider_calls
            provider_calls += 1
            raise httpx.ReadTimeout("provider timed out")

    monkeypatch.setattr(main_module.httpx, "AsyncClient", lambda *args, **kwargs: FailingClient())

    with TestClient(app) as client:
        first = client.post(
            "/api/scans",
            json={"target": "8.8.4.4", "share_with_virustotal": True},
        )
        retry = client.post(
            "/api/scans",
            json={"target": "8.8.4.4", "share_with_virustotal": True},
        )

    assert first.status_code == 201
    assert retry.status_code == 201
    assert first.json()["provider"] == "ThreatScope local analysis"
    assert retry.json()["provider"] == "ThreatScope local analysis"
    assert first.json()["cached"] is False
    assert retry.json()["cached"] is False
    assert first.json()["id"] != retry.json()["id"]
    assert provider_calls == 2
    assert any(item["label"] == "VirusTotal unavailable" for item in first.json()["findings"])


def test_provider_budget_stops_excess_requests(tmp_path):
    database_path = str(tmp_path / "budget.db")
    initialize_database(database_path)

    assert reserve_provider_request(database_path, "virustotal", 1, 400)[0] is True
    allowed, reason = reserve_provider_request(database_path, "virustotal", 1, 400)

    assert allowed is False
    assert reason == "per-minute budget reached"


def test_rejects_unsupported_url_scheme():
    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "ftp://example.com"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Only HTTP and HTTPS URLs can be scanned."


@pytest.mark.parametrize(
    ("status", "finding_label"),
    [
        ("not_found", "VirusTotal report unavailable"),
        ("rate_limited", "VirusTotal quota reached"),
    ],
)
def test_unsuccessful_provider_outcomes_are_persisted_but_not_cached(
    monkeypatch,
    status,
    finding_label,
):
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
    provider_calls = 0

    async def fake_virustotal_report(target, target_type):
        nonlocal provider_calls
        provider_calls += 1
        return ProviderOutcome(
            status=status,
            score=0,
            findings=[
                Finding(
                    label=finding_label,
                    severity="info",
                    detail="Provider result unavailable for this test.",
                )
            ],
        )

    monkeypatch.setattr(main_module, "virustotal_report", fake_virustotal_report)

    with TestClient(app) as client:
        first = client.post(
            "/api/scans",
            json={"target": "1.1.1.1", "share_with_virustotal": True},
        )
        retry = client.post(
            "/api/scans",
            json={"target": "1.1.1.1", "share_with_virustotal": True},
        )
        history = client.get("/api/scans")

    assert first.status_code == 201
    assert retry.status_code == 201
    assert first.json()["cached"] is False
    assert retry.json()["cached"] is False
    assert first.json()["id"] != retry.json()["id"]
    assert provider_calls == 2
    assert history.status_code == 200
    assert len(history.json()) == 2
    assert all(item["provider"] == "ThreatScope local analysis" for item in history.json())


def test_remote_requests_fail_closed_without_access_token(monkeypatch):
    monkeypatch.setattr(main_module, "_loopback_request", lambda request: False)

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 403


def test_remote_requests_accept_configured_access_token(monkeypatch):
    monkeypatch.setattr(main_module, "_loopback_request", lambda request: False)
    monkeypatch.setattr(settings, "access_token", "test-access-token")

    with TestClient(app) as client:
        denied = client.get("/health")
        allowed = client.get("/health", headers={"X-ThreatScope-Key": "test-access-token"})

    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_scan_query_is_analyzed_but_not_persisted(monkeypatch):
    async def fake_local_analysis(original, target, target_type):
        return 5, [Finding(label="Test analysis", severity="info", detail="Complete.")]

    monkeypatch.setattr(main_module, "local_analysis", fake_local_analysis)

    with TestClient(app) as client:
        created = client.post(
            "/api/scans",
            json={"target": "https://example.com/reset?token=super-secret"},
        )
        history = client.get("/api/scans")
        cached = client.post(
            "/api/scans",
            json={"target": "https://example.com/reset?token=super-secret"},
        )

    assert created.status_code == 201
    assert created.json()["target"] == "https://example.com/reset"
    assert "super-secret" not in str(history.json())
    assert cached.json()["cached"] is True
    assert cached.json()["id"] == created.json()["id"]


def test_scan_rate_limit_is_enforced_before_analysis(monkeypatch):
    calls = 0

    async def fake_local_analysis(original, target, target_type):
        nonlocal calls
        calls += 1
        return 5, [Finding(label="Test analysis", severity="info", detail="Complete.")]

    monkeypatch.setattr(main_module, "local_analysis", fake_local_analysis)
    monkeypatch.setattr(settings, "scan_requests_per_minute", 1)

    with TestClient(app) as client:
        first = client.post("/api/scans", json={"target": "8.8.8.8"})
        second = client.post("/api/scans", json={"target": "8.8.4.4"})

    assert first.status_code == 201
    assert second.status_code == 429
    assert calls == 1
